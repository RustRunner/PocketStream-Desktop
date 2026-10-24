//! Machine ownership with an explicit cross-session interactive-user grant.
//! The owning kernel mutex is acquired and released on one dedicated thread.

use std::ptr::{null_mut, NonNull};
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, SetLastError, ERROR_ALREADY_EXISTS, WAIT_ABANDONED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexExW, ReleaseMutex, WaitForSingleObject, MUTEX_MODIFY_STATE,
    SYNCHRONIZATION_SYNCHRONIZE,
};

use super::native_runner::{wide, Handle};

const READ_CONTROL: u32 = 0x20000;
const RIGHTS: u32 = READ_CONTROL | MUTEX_MODIFY_STATE | SYNCHRONIZATION_SYNCHRONIZE;
// Use native mutex masks: object creation maps generic GA to MUTEX_ALL_ACCESS.
const SDDL: &str = "D:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)(A;;0x00120001;;;IU)S:(ML;;NW;;;ME)";

#[derive(Clone, Copy)]
pub(crate) enum Role {
    Host,
    Installation,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::Host => "Global\\PocketStream.Desktop.HostOwner.v2",
            Self::Installation => "Global\\PocketStream.Desktop.InstallGate.v2",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OwnershipError {
    Busy,
    NamespaceOrSecurity(u32),
    DescriptorMismatch { expected: String, observed: String },
    OwnerThreadUnavailable,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct Acquisition {
    pub newly_created: bool,
    pub abandoned: bool,
    pub security_descriptor: String,
}

struct LocalAllocation(NonNull<std::ffi::c_void>);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0.as_ptr()) };
    }
}

fn descriptor_string(sd: *mut std::ffi::c_void) -> Result<String, OwnershipError> {
    let mut value = null_mut();
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut value,
            null_mut(),
        )
    } == 0
    {
        return Err(OwnershipError::NamespaceOrSecurity(unsafe {
            GetLastError()
        }));
    }
    let allocation = LocalAllocation(NonNull::new(value.cast()).unwrap());
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) });
    drop(allocation);
    Ok(result)
}

fn open_and_acquire(name: &str, wait: Duration) -> Result<(Handle, Acquisition), OwnershipError> {
    let mut security_descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(std::ffi::OsStr::new(SDDL)).as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(OwnershipError::NamespaceOrSecurity(unsafe {
            GetLastError()
        }));
    }
    let descriptor = LocalAllocation(NonNull::new(security_descriptor).unwrap());
    let expected = descriptor_string(security_descriptor)?;
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor,
        bInheritHandle: 0,
    };
    unsafe { SetLastError(0) };
    let raw = unsafe {
        CreateMutexExW(
            &security,
            wide(std::ffi::OsStr::new(name)).as_ptr(),
            0,
            RIGHTS,
        )
    };
    let create_error = unsafe { GetLastError() };
    let handle =
        Handle::checked(raw).map_err(|_| OwnershipError::NamespaceOrSecurity(create_error))?;
    drop(descriptor);

    let mut actual_descriptor = null_mut();
    let error = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut actual_descriptor,
        )
    };
    if error != 0 {
        return Err(OwnershipError::NamespaceOrSecurity(error));
    }
    let allocation = LocalAllocation(NonNull::new(actual_descriptor).unwrap());
    let actual = descriptor_string(actual_descriptor)?;
    drop(allocation);
    // Windows marks the created label SACL auto-inherited even though its sole
    // ACE remains explicit. Ignore only that bookkeeping bit; rights, trustees,
    // protected DACL, ACE flags and the Medium no-write-up label must all match.
    if actual.replace("S:AI(", "S:(") != expected {
        return Err(OwnershipError::DescriptorMismatch {
            expected,
            observed: actual,
        });
    }
    let result = unsafe { WaitForSingleObject(handle.0, wait.as_millis().min(5000) as u32) };
    match result {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok((
            handle,
            Acquisition {
                newly_created: create_error != ERROR_ALREADY_EXISTS,
                abandoned: result == WAIT_ABANDONED,
                security_descriptor: actual,
            },
        )),
        WAIT_TIMEOUT => Err(OwnershipError::Busy),
        _ => Err(OwnershipError::NamespaceOrSecurity(unsafe {
            GetLastError()
        })),
    }
}

pub(crate) struct MachineGuard {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    pub acquisition: Acquisition,
}
impl MachineGuard {
    // Production accepts only fixed roles; arbitrary names exist only in tests.
    pub fn acquire(role: Role, wait: Duration) -> Result<Self, OwnershipError> {
        Self::acquire_name(role.name().to_string(), wait)
    }

    #[cfg(test)]
    pub fn acquire_fixture(
        nonce: &str,
        role: Role,
        wait: Duration,
    ) -> Result<Self, OwnershipError> {
        assert!(nonce.len() == 32 && nonce.bytes().all(|c| c.is_ascii_hexdigit()));
        let suffix = role.name().rsplit('\\').next().unwrap();
        Self::acquire_name(
            format!("Global\\PocketStream.Qualification.{nonce}.{suffix}"),
            wait,
        )
    }

    fn acquire_name(name: String, wait: Duration) -> Result<Self, OwnershipError> {
        let (ready_tx, ready) = mpsc::sync_channel(1);
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("native-state-owner".into())
            .spawn(move || match open_and_acquire(&name, wait) {
                Ok((handle, acquisition)) => {
                    let _ = ready_tx.send(Ok(acquisition));
                    let _ = stopped.recv();
                    unsafe { ReleaseMutex(handle.0) };
                    // The handle closes on this same thread after release.
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            })
            .map_err(|_| OwnershipError::OwnerThreadUnavailable)?;
        match ready.recv_timeout(wait.min(Duration::from_secs(5)) + Duration::from_secs(2)) {
            Ok(Ok(acquisition)) => Ok(Self {
                stop: Some(stop),
                thread: Some(thread),
                acquisition,
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => Err(OwnershipError::OwnerThreadUnavailable),
        }
    }
}
impl Drop for MachineGuard {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
