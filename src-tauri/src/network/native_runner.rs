//! Trusted Windows child ownership. Only fixed typed policies reach this runner.

use std::collections::BTreeMap;
use std::ffi::{c_void, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
#[cfg(test)]
use serde::Deserialize;
use windows_sys::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JobObjectBasicProcessIdList,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemInformation::{
    GetSystemDirectoryW, GetSystemWindowsDirectoryW,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcess, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    SYNCHRONIZATION_SYNCHRONIZE,
};

pub(super) const OUTPUT_CAP: usize = 32 * 1024;
const INPUT_CAP: usize = 16 * 1024;
const CANCELED_EXIT: u32 = 0xc000013a;

#[derive(Clone, Default)]
pub(super) struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub(super) struct Handle(pub HANDLE);
// Kernel handles can be transferred; mutex ownership itself stays on its thread.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
impl Handle {
    pub fn checked(raw: HANDLE) -> std::io::Result<Self> {
        if raw.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}

pub(super) fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

pub(super) fn system_directory() -> std::io::Result<PathBuf> {
    trusted_directory(GetSystemDirectoryW)
}
fn trusted_directory(
    api: unsafe extern "system" fn(*mut u16, u32) -> u32,
) -> std::io::Result<PathBuf> {
    let mut buf = vec![0; 32768];
    let count = unsafe { api(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if count == 0 || count >= buf.len() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsString::from_wide(&buf[..count])))
}

#[cfg(test)]
#[derive(Clone)]
pub(super) enum QualificationOperation {
    Echo(String),
    RequiredCmdletFailure,
    RequiredNativeFailure,
    ProductionNativeFailure,
    ChildTree,
    FloodOutput,
}
#[cfg(test)]
impl QualificationOperation {
    fn payload(&self) -> Result<Vec<u8>, &'static str> {
        let (kind, value) = match self {
            Self::Echo(value) if value.chars().count() <= 4096 => ("echo", value.as_str()),
            Self::Echo(_) => return Err("qualification value too large"),
            Self::RequiredCmdletFailure => ("cmdlet_failure", ""),
            Self::RequiredNativeFailure => ("native_failure", ""),
            Self::ProductionNativeFailure => ("production_native_failure", ""),
            Self::ChildTree => ("child_tree", ""),
            Self::FloodOutput => ("flood_output", ""),
        };
        let payload = serde_json::to_vec(&serde_json::json!({
            "version": 1, "kind": kind, "value": value
        }))
        .map_err(|_| "payload encoding failed")?;
        if payload.len() > INPUT_CAP {
            return Err("payload too large");
        }
        Ok(payload)
    }
}

#[cfg(test)]
pub(super) const QUALIFICATION_SCRIPT: &str =
    include_str!("../../tests/fixtures/native-runner-v1.ps1");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Termination {
    Exited,
    Canceled,
    TimedOut,
}

#[derive(Default, Debug)]
pub(super) struct Captured {
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub read_failed: bool,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StepResult {
    pub version: u32,
    pub ok: bool,
    pub stage: String,
    pub value: Option<String>,
    pub ast_text: Option<String>,
    pub ps_version: Option<String>,
    pub cwd: Option<String>,
    pub autoload: Option<String>,
    pub module_paths: Option<Vec<String>>,
    pub native_exit: Option<i32>,
}

#[derive(Debug)]
pub(super) struct ProcessResult {
    pub exit_code: u32,
    pub termination: Termination,
    pub stdout: Captured,
    pub stderr: Captured,
    pub observed_tree_pids: Vec<u32>,
    pub observed_tree_exited: bool,
    pub containment_verified_before_resume: bool,
    pub elapsed: Duration,
}
impl ProcessResult {
    #[cfg(test)]
    pub fn structured(&self) -> Result<StepResult, &'static str> {
        if self.stdout.truncated || self.stderr.truncated {
            return Err("native output truncated");
        }
        if self.stdout.read_failed || self.stderr.read_failed {
            return Err("native output unavailable");
        }
        let result: StepResult =
            serde_json::from_slice(&self.stdout.bytes).map_err(|_| "invalid structured result")?;
        if result.version != 1 || result.ok != (self.exit_code == 0) {
            return Err("inconsistent structured result");
        }
        Ok(result)
    }
}

fn pipe(parent_reads: bool) -> std::io::Result<(Handle, File)> {
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (null_mut(), null_mut());
    if unsafe { CreatePipe(&mut read, &mut write, &security, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (child, parent) = if parent_reads {
        (Handle(write), Handle(read))
    } else {
        (Handle(read), Handle(write))
    };
    if unsafe { SetHandleInformation(parent.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(parent.0 as RawHandle) };
    std::mem::forget(parent); // File now owns exactly this handle.
    Ok((child, file))
}

fn drain(mut pipe: File) -> Captured {
    let mut result = Captured::default();
    let mut buf = [0; 4096];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => return result,
            Ok(count) => {
                let keep = count.min(OUTPUT_CAP - result.bytes.len());
                result.bytes.extend_from_slice(&buf[..keep]);
                result.truncated |= keep != count;
            }
            Err(_) => {
                result.read_failed = true;
                return result;
            }
        }
    }
}

struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new(handles: &mut [HANDLE], jobs: &mut [HANDLE]) -> std::io::Result<Self> {
        let mut bytes = 0;
        unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes) };
        let mut result = Self {
            storage: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        if unsafe { InitializeProcThreadAttributeList(result.pointer(), 2, 0, &mut bytes) } == 0 {
            // The attribute list was not initialized; don't call its destructor.
            return Err(std::io::Error::last_os_error());
        }
        result.initialized = true;
        if unsafe {
            UpdateProcThreadAttribute(
                result.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // Assign at CreateProcess as well as keeping the primary thread
        // suspended. A supervisor crash cannot strand an unassigned child.
        if unsafe {
            UpdateProcThreadAttribute(
                result.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                std::mem::size_of_val(jobs),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(result)
    }
    fn pointer(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.pointer()) };
        }
    }
}

#[repr(C)]
struct JobPids {
    assigned: u32,
    listed: u32,
    pids: [usize; 64],
}
fn observe_tree(job: &Handle, processes: &mut BTreeMap<u32, Handle>) -> std::io::Result<()> {
    let mut ids: JobPids = unsafe { zeroed() };
    if unsafe {
        QueryInformationJobObject(
            job.0,
            JobObjectBasicProcessIdList,
            (&mut ids as *mut JobPids).cast(),
            size_of::<JobPids>() as u32,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    for id in &ids.pids[..ids.listed as usize] {
        let pid = *id as u32;
        if let std::collections::btree_map::Entry::Vacant(entry) = processes.entry(pid) {
            let raw = unsafe {
                OpenProcess(
                    SYNCHRONIZATION_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                )
            };
            // A process which already exited may no longer have an openable PID.
            if !raw.is_null() {
                entry.insert(Handle(raw));
            }
        }
    }
    Ok(())
}

pub(super) struct NativeProcessRunner;
impl NativeProcessRunner {
    // Diagnostic only: reuse the real runner/budget. The read-only variant
    // intercepts every writer; the separate provider test needs explicit opt-in.
    #[cfg(test)]
    fn firewall_startup_probe(read_only: bool) -> Result<ProcessResult, String> {
        let script = super::firewall::SCRIPT.replace(
            "# @TRUSTED_IMPORTS_END@",
            include_str!("../../tests/fixtures/firewall-read-only-v1.ps1"),
        );
        let script = script.replace(
            "function All-Rules { return @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop) }",
            "function All-Rules { $w=[Diagnostics.Stopwatch]::StartNew(); try { return @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop) } finally { [Console]::Error.WriteLine(('read_all_ms='+$w.ElapsedMilliseconds)) } }",
        );
        let script = script.replace(
            "function Shape($rule) {",
            "function Shape($rule) { [Console]::Error.WriteLine(('shape_begin='+$rule.Name)); $w=[Diagnostics.Stopwatch]::StartNew()",
        ).replace(
            "    if ($app.Count -ne 1",
            "    [Console]::Error.WriteLine(('shape_ms='+$w.ElapsedMilliseconds))\n    if ($app.Count -ne 1",
        );
        let mut payload: serde_json::Value =
            serde_json::from_slice(&super::firewall::Operation::Startup.payload()?)
                .map_err(|e| e.to_string())?;
        payload["program"] =
            serde_json::json!(r"C:\Program Files\PocketStream Desktop\pocketstream-desktop.exe");
        Self::run_inner(
            if read_only {
                &script
            } else {
                super::firewall::SCRIPT
            },
            serde_json::to_vec(&payload).map_err(|e| e.to_string())?,
            Cancellation::default(),
            Duration::from_secs(30),
            None,
        )
        .map_err(|e| e.to_string())
    }

    // There is no program/script/argument/environment-map entry point. The
    // qualification operation picks one fixed source and bounded JSON input.
    #[cfg(test)]
    pub fn run(
        operation: QualificationOperation,
        cancel: Cancellation,
        budget: Duration,
        dispatched: Option<tokio::sync::oneshot::Sender<u32>>,
    ) -> Result<ProcessResult, String> {
        let payload = operation.payload().map_err(str::to_string)?;
        let source = if matches!(operation, QualificationOperation::ProductionNativeFailure) {
            // Only compile-time fixed source contributes to this test script.
            // Reuse the actual production function to catch PS scope regressions.
            let production = super::native_operations::SCRIPT;
            let start = production
                .find("function Native(")
                .ok_or("missing production native helper")?;
            let end = production[start..]
                .find("\nfunction Check-Host(")
                .ok_or("missing production helper boundary")?
                + start;
            include_str!("../../tests/fixtures/production-native-failure-v1.ps1")
                .replace("# @PRODUCTION_NATIVE_HELPER@", &production[start..end])
        } else {
            QUALIFICATION_SCRIPT.to_string()
        };
        Self::run_inner(&source, payload, cancel, budget, dispatched)
            .map_err(|_| "Trusted native process setup or containment failed".into())
    }

    pub fn run_operation(
        operation: super::native_operations::Operation,
        cancel: Cancellation,
    ) -> Result<ProcessResult, String> {
        let payload = operation.payload().map_err(|e| e.to_string())?;
        Self::run_inner(
            super::native_operations::SCRIPT,
            payload,
            cancel,
            Duration::from_secs(30),
            None,
        )
        .map_err(|error| {
            format!(
                "Trusted native process setup or containment failed ({:?}, Windows code {:?})",
                error.kind(),
                error.raw_os_error()
            )
        })
    }

    pub(super) fn run_firewall(
        operation: super::firewall::Operation,
        cancel: Cancellation,
    ) -> Result<ProcessResult, String> {
        Self::run_inner(
            super::firewall::SCRIPT,
            operation.payload()?,
            cancel,
            Duration::from_secs(30),
            None,
        )
        .map_err(|error| {
            format!(
                "Trusted firewall process setup or containment failed ({:?}, Windows code {:?})",
                error.kind(),
                error.raw_os_error()
            )
        })
    }

    fn run_inner(
        script: &str,
        payload: Vec<u8>,
        cancel: Cancellation,
        budget: Duration,
        dispatched: Option<tokio::sync::oneshot::Sender<u32>>,
    ) -> std::io::Result<ProcessResult> {
        let start = Instant::now();
        if payload.len() > INPUT_CAP {
            return Err(std::io::Error::other("native input too large"));
        }
        let system = system_directory()?;
        let windows = trusted_directory(GetSystemWindowsDirectoryW)?;
        let ps = system.join("WindowsPowerShell\\v1.0\\powershell.exe");
        let application = wide(ps.as_os_str());
        // Only compile-time fixed source enters this UTF-8 bootstrap. JSON
        // operation data stays on stdin. One base64 layer leaves room under
        // the Windows command-line bound without transforming the script AST.
        let encoded = base64::engine::general_purpose::STANDARD.encode(script.as_bytes());
        let bootstrap = format!("& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))))");
        let mut command = wide(std::ffi::OsStr::new(&format!(
            "\"{}\" -NoLogo -NoProfile -NonInteractive -Command \"{}\"",
            ps.display(),
            bootstrap
        )));
        if command.len() > 32767 {
            return Err(std::io::Error::other(
                "fixed native source exceeds command-line limit",
            ));
        }
        let env = BTreeMap::from([
            ("PATH", system.as_os_str().to_owned()),
            // PS 5.1 otherwise shell-opens even an absolute .exe and can
            // return without a native exit code when PATHEXT is absent.
            ("PATHEXT", OsString::from(".EXE")),
            (
                "PSModulePath",
                system
                    .join("WindowsPowerShell\\v1.0\\Modules")
                    .into_os_string(),
            ),
            ("SystemRoot", windows.as_os_str().to_owned()),
            ("TEMP", system.as_os_str().to_owned()),
            ("TMP", system.as_os_str().to_owned()),
            ("windir", windows.as_os_str().to_owned()),
        ]);
        let mut environment = Vec::<u16>::new();
        for (key, value) in env {
            environment.extend(OsString::from(format!("{key}=")).encode_wide());
            environment.extend(value.encode_wide());
            environment.push(0);
        }
        environment.push(0);

        let job = Handle::checked(unsafe { CreateJobObjectW(null(), null()) })?;
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let (stdin_child, mut stdin) = pipe(false)?;
        let (stdout_child, stdout) = pipe(true)?;
        let (stderr_child, stderr) = pipe(true)?;
        let mut inherited = [stdin_child.0, stdout_child.0, stderr_child.0];
        let mut jobs = [job.0];
        let mut attributes = Attributes::new(&mut inherited, &mut jobs)?;
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin_child.0;
        startup.StartupInfo.hStdOutput = stdout_child.0;
        startup.StartupInfo.hStdError = stderr_child.0;
        startup.lpAttributeList = attributes.pointer();
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                wide(system.as_os_str()).as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let process = Handle(info.hProcess);
        let thread = Handle(info.hThread);
        let mut contained = 0;
        if unsafe { IsProcessInJob(process.0, job.0, &mut contained) } == 0 || contained == 0 {
            // Never resume a child when containment cannot be verified.
            unsafe { TerminateProcess(process.0, CANCELED_EXIT) };
            return Err(std::io::Error::last_os_error());
        }
        drop((stdin_child, stdout_child, stderr_child, attributes));
        let stdout_drain = std::thread::spawn(move || drain(stdout));
        let stderr_drain = std::thread::spawn(move || drain(stderr));
        let input = std::thread::spawn(move || stdin.write_all(&payload));
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            unsafe { TerminateJobObject(job.0, CANCELED_EXIT) };
            return Err(std::io::Error::last_os_error());
        }
        if let Some(dispatched) = dispatched {
            let _ = dispatched.send(info.dwProcessId);
        }
        let mut processes = BTreeMap::new();
        let budget = budget.clamp(Duration::from_millis(250), Duration::from_secs(30));
        let termination = loop {
            if observe_tree(&job, &mut processes).is_err() {
                unsafe { TerminateJobObject(job.0, CANCELED_EXIT) };
                break Termination::Canceled;
            }
            if unsafe { WaitForSingleObject(process.0, 20) } == WAIT_OBJECT_0 {
                break Termination::Exited;
            }
            if cancel.requested() {
                break Termination::Canceled;
            }
            if start.elapsed() >= budget {
                break Termination::TimedOut;
            }
        };
        // Also retire descendants of an already-exited parent before joining
        // drains: an inherited pipe must not keep an orphan reader blocked.
        unsafe { TerminateJobObject(job.0, CANCELED_EXIT) };
        if unsafe { WaitForSingleObject(process.0, 5000) } != WAIT_OBJECT_0 {
            return Err(std::io::Error::other("native child did not drain"));
        }
        let all_exited = processes
            .values()
            .all(|handle| unsafe { WaitForSingleObject(handle.0, 5000) } == WAIT_OBJECT_0);
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let _ = input.join();
        let stdout = stdout_drain
            .join()
            .map_err(|_| std::io::Error::other("stdout drain failed"))?;
        let stderr = stderr_drain
            .join()
            .map_err(|_| std::io::Error::other("stderr drain failed"))?;
        Ok(ProcessResult {
            exit_code,
            termination,
            stdout,
            stderr,
            observed_tree_pids: processes.keys().copied().collect(),
            observed_tree_exited: all_exited,
            containment_verified_before_resume: true,
            elapsed: start.elapsed(),
        })
    }
}

#[cfg(test)]
#[test]
#[ignore = "Explicit target read-only startup timing; all firewall writes intercepted"]
fn qualify_firewall_startup_read_only() {
    assert_eq!(
        std::env::var("POCKETSTREAM_READ_ONLY_FIREWALL_PROBE").as_deref(),
        Ok("1")
    );
    let p = NativeProcessRunner::firewall_startup_probe(true).unwrap();
    print_firewall_probe(&p, true);
    assert!(p.containment_verified_before_resume && p.observed_tree_exited);
}

#[cfg(test)]
#[test]
#[ignore = "Requires explicit approval: real startup disables of the two installed owned rules"]
fn qualify_firewall_startup_provider() {
    assert_eq!(
        std::env::var("POCKETSTREAM_FIREWALL_PROVIDER_PROBE").as_deref(),
        Ok("approved-disabled-installed-rules")
    );
    let p = NativeProcessRunner::firewall_startup_probe(false).unwrap();
    print_firewall_probe(&p, false);
    assert!(p.containment_verified_before_resume && p.observed_tree_exited);
}

#[cfg(test)]
fn print_firewall_probe(p: &ProcessResult, read_only: bool) {
    println!(
        "FIREWALL_READ_PROBE={}",
        serde_json::json!({
            "termination":format!("{:?}",p.termination),"exit_code":p.exit_code,
            "elapsed_ms":p.elapsed.as_millis(),"contained":p.containment_verified_before_resume,
            "tree_exited":p.observed_tree_exited,"tree_pids":p.observed_tree_pids,
            "stdout":String::from_utf8_lossy(&p.stdout.bytes),
            "stderr":String::from_utf8_lossy(&p.stderr.bytes),
            "stdout_truncated":p.stdout.truncated,"stderr_truncated":p.stderr.truncated,
            "stdout_read_failed":p.stdout.read_failed,"stderr_read_failed":p.stderr.read_failed,
            "firewall_writes_intercepted":read_only
        })
    );
}
