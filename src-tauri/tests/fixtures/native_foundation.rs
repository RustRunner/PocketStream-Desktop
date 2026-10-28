//! Explicit Windows process fixtures for prerequisite A-S2/A-S4 and v0.6.8 reads.
//! Loaded in the network test module to reuse its private fake seams.
//! Kept out of ordinary unit runs. Native addresses are existing AddressIo /
//! AdoptOps fakes. The separately opted-in v0.6.8 diagnostic sends bounded TCP
//! probes on two already applied /24s and verifies fresh selected-interface MACs;
//! it never configures an adapter, sends PTU commands or qualifies B-S1.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::auto_adopt::{AdoptOps, PendingAdoptOps};
use super::host_owner::{MachineGuard, OwnershipError, Role};
use super::interface::address_test_io::{Effect, FakeAddressIo};
use super::interface::{self, AddressIo};
use super::local_executor::{AdmissionError, Completion, LocalExecutor, Outcome};
use super::native_runner::{
    system_directory, Cancellation, NativeProcessRunner, QualificationOperation, Termination,
    OUTPUT_CAP, QUALIFICATION_SCRIPT,
};
use super::AddressOps;
use crate::config::{AppConfig, AppSettings, NetworkMode};

#[tokio::test]
#[ignore = "Explicit v0.6.8 target read-only bound /24 probes; no adapter changes or PTU commands"]
async fn diagnose_v068_bound_discovery_read_only() {
    assert_eq!(
        std::env::var("POCKETSTREAM_V068_BOUND_READ").as_deref(),
        Ok("1")
    );
    let started = Instant::now();
    let before = interface::read_native().await.unwrap();
    let native = before.iter().find(|a| a.index == 13).unwrap();
    assert_eq!(
        native.identity().guid,
        "86193159-40f0-4a29-a389-c4c0b1945e82"
    );
    assert_eq!(native.identity().mac, "00:22:20:3a:e3:b3");
    assert!(native.is_up);
    let adapters = interface::list_all_adapters().await.unwrap();
    let selected = adapters
        .iter()
        .find(|a| a.mac.eq_ignore_ascii_case(&native.mac))
        .unwrap();
    assert!(
        selected.is_up
            && selected.is_ethernet
            && !selected.is_wifi
            && !selected.is_virtual
            && !selected.is_vpn
    );
    let mut records = Vec::new();
    for (subnet, source) in [
        ("192.168.1.0/24", "192.168.1.100"),
        ("10.131.50.0/24", "10.131.50.100"),
    ] {
        assert!(native
            .ips
            .iter()
            .any(|a| a.address == source && a.prefix == 24));
        println!("BOUND_READ_BEGIN={subnet}");
        let results = super::scanner::scan(
            subnet,
            super::scanner::ScanScope {
                index: 13,
                ips: selected.ips.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        for result in results.into_iter().filter(|r| r.reachable) {
            let target = result.ip.parse().unwrap();
            let source = result.source.as_ref().unwrap().parse().unwrap();
            let mac = super::arp::fresh_resolve_mac(target, source, 13).await;
            records.push(json!({"ip":result.ip,"source":result.source,"interface_index":13,
                "ports":result.open_ports,"fresh_mac_after_probe":mac.as_ref().ok().and_then(|m|m.clone()),
                "fresh_resolution_error":mac.err().map(|e|e.to_string())}));
        }
    }
    let after = interface::read_native().await.unwrap();
    let current = after.iter().find(|a| a.index == 13).unwrap();
    assert_eq!(current.guid, native.guid);
    assert_eq!(current.mac, native.mac);
    assert!(current.is_up);
    assert_eq!(
        serde_json::to_value(&current.ips).unwrap(),
        serde_json::to_value(&native.ips).unwrap()
    );
    println!(
        "BOUND_READ_RESULT={}",
        json!({"elapsed_ms":started.elapsed().as_millis(),"records":records,
        "adapter_configuration_unchanged":true,"ptu_commands":0,"B_S1_credit":false,
        "scope":"diagnostic TCP probes plus fresh selected-interface neighbor verification; not unassisted discovery qualification"})
    );
}

fn evidence_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let run = std::env::var("POCKETSTREAM_NATIVE_PROOF_RUN")
            .unwrap_or_else(|_| format!("run-{}", std::process::id()));
        assert!(run.len() <= 64 && run.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/privilege-a2-proofs")
            .join(run);
        fs::create_dir_all(&root).unwrap();
        root
    })
}
fn record(name: &str, mut value: Value) {
    value["recorded_at_utc"] = json!(chrono::Utc::now().to_rfc3339());
    value["test_executable"] = json!(std::env::current_exe().unwrap());
    value["test_process_id"] = json!(std::process::id());
    fs::write(
        evidence_root().join(format!("{name}.json")),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
}
fn config_for(io: &FakeAddressIo) -> Arc<AppConfig> {
    Arc::new(AppConfig::temporary_test_config(AppSettings {
        selected_adapter_mac: Some(io.table.lock().unwrap()[0].mac.clone()),
        network_mode: NetworkMode::StaticAuto,
        ..Default::default()
    }))
}
fn new_executor() -> LocalExecutor {
    LocalExecutor::for_serialized_writers()
}

#[test]
#[ignore = "A2 actual fixed-policy inventory; reads native adapters only"]
fn qualify_typed_inventory_read_only() {
    let process = NativeProcessRunner::run_operation(
        super::native_operations::Operation::inventory(),
        Cancellation::default(),
    )
    .unwrap();
    assert_eq!(process.termination, Termination::Exited);
    assert_eq!(
        process.exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&process.stdout.bytes)
    );
    assert!(!process.stdout.truncated && !process.stderr.truncated);
    let report: Value = serde_json::from_slice(&process.stdout.bytes).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["mutated"], false);
    assert!(report["data"].is_array());
    assert_eq!(report["steps"][0]["name"], "inventory");
    record(
        "typed-production-inventory",
        json!({"exit_code":process.exit_code,
        "contained_before_resume":process.containment_verified_before_resume,
        "tree_exited":process.observed_tree_exited,"report":report,
        "native_address_firewall_or_install_mutation":false}),
    );
}

#[test]
#[ignore = "A2 actual production native function; fixed invalid ipconfig option only"]
fn qualify_production_native_exit_status() {
    let process = NativeProcessRunner::run(
        QualificationOperation::ProductionNativeFailure,
        Cancellation::default(),
        Duration::from_secs(10),
        None,
    )
    .unwrap();
    let report = process.structured().unwrap();
    assert_eq!(process.exit_code, 71);
    assert_eq!(report.native_exit, Some(1));
    assert_eq!(report.stage, "required_native");
    assert!(process.observed_tree_exited);
    record(
        "production-native-required-failure",
        json!({"process_exit":process.exit_code,
        "native_exit":report.native_exit,"ps_version":report.ps_version,
        "production_helper_reused":true,"address_firewall_install_mutation":false}),
    );
}

#[tokio::test]
#[ignore = "A2 native system DLL/neighbor reads and optional controlled ICMP; no network configuration writes"]
async fn qualify_native_observation_paths() {
    interface::list_all_adapters().await.unwrap();
    let _api = super::pktmon::PktMonApi::load().expect("trusted system capture DLL");
    let adapters = interface::read_native().await.unwrap();
    let mut observed = vec![];
    for adapter in adapters.iter().filter(|a| {
        interface::RealAddressIo
            .descriptor(a)
            .is_some_and(|i| interface::is_wired_physical(&i))
    }) {
        let operation = super::native_operations::Operation::observe(adapter).unwrap();
        let request = operation.clone();
        let process = tokio::task::spawn_blocking(move || {
            NativeProcessRunner::run_operation(request, Cancellation::default())
        })
        .await
        .unwrap()
        .unwrap();
        let after = interface::read_native().await.unwrap();
        let after = interface::select_native(&after, &adapter.mac).unwrap();
        let (completion, reply) = super::native_operations::evaluate_result(
            &operation,
            Some(adapter),
            Some(after),
            &process,
        );
        assert_eq!(completion.outcome, Outcome::Completed, "{:?}", reply);
        reply.unwrap();
        observed.push(json!({"index":adapter.index,"addresses_dhcp_routes_dns_observed":true,"mutated":false}));
    }
    assert!(
        !observed.is_empty(),
        "No physical Ethernet state was qualified"
    );
    let source = adapters
        .iter()
        .flat_map(|a| &a.ips)
        .filter_map(|ip| ip.address.parse::<std::net::Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified());
    let neighbors = if let Some(source) = source {
        Some(super::arp::native_neighbors(source).await.unwrap().len())
    } else {
        None
    };
    let probe = match (
        std::env::var("POCKETSTREAM_NATIVE_PROBE_SOURCE"),
        std::env::var("POCKETSTREAM_NATIVE_PROBE_TARGET"),
    ) {
        (Ok(source), Ok(target)) => {
            let source: std::net::Ipv4Addr = source.parse().unwrap();
            let target: std::net::Ipv4Addr = target.parse().unwrap();
            let owner = adapters
                .iter()
                .find(|a| a.ips.iter().any(|ip| ip.address == source.to_string()))
                .expect("fixture source is applied");
            let reply =
                super::arp::bound_ping(target, source, owner.index, Duration::from_millis(1000))
                    .await
                    .unwrap();
            Some(json!({"source":source,"target":target,"index":owner.index,"echo_reply":reply}))
        }
        _ => None,
    };
    record(
        "native-observation-paths",
        json!({"system_capture_dll_loaded":true,"capture_started":false,
        "neighbor_source":source,"neighbor_entries":neighbors,"controlled_icmp":probe,
            "selected_state_observations":observed,
        "address_firewall_install_mutation":false}),
    );
}
async fn initial_observation(executor: &LocalExecutor) {
    executor
        .reconcile(|_| async { Completion::new(Outcome::Completed, "initial_native_observation") })
        .unwrap()
        .wait()
        .await
        .unwrap();
}

#[test]
#[ignore = "A-S2 read-only Windows PowerShell process fixture"]
fn qualify_script_data_and_required_failures() {
    let cases = [
        "Ethernet",
        "ASCII 'single' and \"double\"; $(exit 96); `backtick`",
        "Smart ‘single’ “double”; Ω 中文 日本語 🛰️",
        "line one\r\nline two\nline three\rline four",
        "Ethernet*[?]'; exit 97; #",
    ];
    let system = system_directory().unwrap();
    let mut observed = vec![];
    for value in cases {
        let process = NativeProcessRunner::run(
            QualificationOperation::Echo(value.into()),
            Cancellation::default(),
            Duration::from_secs(10),
            None,
        )
        .unwrap();
        let result = process.structured().unwrap_or_else(|reason| {
            record("script-fixture-failure", json!({"reason":reason,"exit_code":process.exit_code,"stderr":String::from_utf8_lossy(&process.stderr.bytes)}));
            panic!(
                "{reason}; exit {}; stdout bytes {}; stderr bytes {}",
                process.exit_code,
                process.stdout.bytes.len(),
                process.stderr.bytes.len()
            )
        });
        assert!(result.ok);
        assert_eq!(result.stage, "echo");
        assert_eq!(result.value.as_deref(), Some(value));
        assert_eq!(result.ast_text.as_deref(), Some(QUALIFICATION_SCRIPT));
        assert!(result.ps_version.as_deref().unwrap().starts_with("5.1."));
        assert_eq!(Path::new(result.cwd.as_ref().unwrap()), system);
        assert_eq!(result.autoload.as_deref(), Some("None"));
        assert!(result
            .module_paths
            .as_ref()
            .unwrap()
            .iter()
            .all(|path| Path::new(path).starts_with(&system)));
        assert!(process.containment_verified_before_resume);
        assert_eq!(process.termination, Termination::Exited);
        observed.push(json!({"case":observed.len(),"round_trip":true,"ast_unchanged":true,"ps_version":result.ps_version,"exit_code":process.exit_code,"elapsed_ms":process.elapsed.as_millis()}));
    }
    let mut failures = vec![];
    for (operation, stage) in [
        (
            QualificationOperation::RequiredCmdletFailure,
            "required_cmdlet",
        ),
        (
            QualificationOperation::RequiredNativeFailure,
            "required_native",
        ),
    ] {
        let process = NativeProcessRunner::run(
            operation,
            Cancellation::default(),
            Duration::from_secs(10),
            None,
        )
        .unwrap();
        let result = process.structured().unwrap();
        assert!(!result.ok);
        assert_eq!(result.stage, stage);
        assert_ne!(process.exit_code, 0);
        if stage == "required_native" {
            assert_ne!(result.native_exit.unwrap(), 0);
        }
        failures.push(json!({"stage":stage,"failed_typed_result":true,"process_exit_code":process.exit_code,"native_exit_code":result.native_exit}));
    }
    assert!(NativeProcessRunner::run(
        QualificationOperation::Echo("x".repeat(4097)),
        Cancellation::default(),
        Duration::from_secs(10),
        None
    )
    .is_err());
    record(
        "script-data-and-required-failures",
        json!({"gate":"A-S2","cases":observed,"failures":failures,"oversized_input_rejected":true,"system_directory":system,"modules":"explicit protected Utility, Management and CimCmdlets; autoload None","network_or_firewall_mutation":false}),
    );
}

#[test]
#[ignore = "A-S2 private child-job timeout/output fixture"]
fn qualify_child_tree_and_bounded_output() {
    let process = NativeProcessRunner::run(
        QualificationOperation::ChildTree,
        Cancellation::default(),
        Duration::from_secs(4),
        None,
    )
    .unwrap();
    assert_eq!(process.termination, Termination::TimedOut);
    assert!(
        process.observed_tree_pids.len() >= 2,
        "grandchild never entered job"
    );
    assert!(process.observed_tree_exited);
    assert!(process.containment_verified_before_resume);
    let timeout = json!({"termination":"timed_out","observed_tree_pids":process.observed_tree_pids,"all_retained_process_handles_signaled":process.observed_tree_exited,"elapsed_ms":process.elapsed.as_millis(),"assigned_while_suspended":true});
    let process = NativeProcessRunner::run(
        QualificationOperation::FloodOutput,
        Cancellation::default(),
        Duration::from_secs(10),
        None,
    )
    .unwrap();
    assert_eq!(process.exit_code, 0);
    assert_eq!(process.stdout.bytes.len(), OUTPUT_CAP);
    assert_eq!(process.stderr.bytes.len(), OUTPUT_CAP);
    assert!(process.stdout.truncated && process.stderr.truncated);
    assert_eq!(process.structured().unwrap_err(), "native output truncated");
    record(
        "child-tree-and-output",
        json!({"gate":"A-S2","timeout":timeout,"output":{"stdout_cap":process.stdout.bytes.len(),"stderr_cap":process.stderr.bytes.len(),"both_truncated":true,"oversized_structured_result_rejected":true,"exit_code":process.exit_code},"network_or_firewall_mutation":false}),
    );
}

// Uses the existing write-ahead configuration rows, identity/qualification
// provider and PendingAdoptOps recovery; no second native-address model.
async fn reconcile_existing(config: Arc<AppConfig>, io: Arc<FakeAddressIo>) -> Completion {
    let all = match io.native().await {
        Ok(all) => all,
        Err(_) => return Completion::new(Outcome::Uncertain, "native_observation_unavailable"),
    };
    for row in config.get().pending_addresses {
        let owners: Vec<_> = all
            .iter()
            .filter(|n| n.identity().mac == row.adapter_mac)
            .collect();
        let [native] = owners.as_slice() else {
            return Completion::new(Outcome::Uncertain, "pending_adapter_identity_conflict");
        };
        if io
            .descriptor(native)
            .filter(interface::is_wired_physical)
            .is_none()
        {
            return Completion::new(Outcome::Uncertain, "pending_adapter_unqualified");
        }
        let ops = PendingAdoptOps {
            config: config.as_ref(),
            adapter_mac: &row.adapter_mac,
            ops: AddressOps(io.as_ref(), None),
            persist: |_| Ok(()),
        };
        if ops
            .remove(&native.alias, row.address.parse().unwrap())
            .await
            .is_err()
        {
            return Completion::new(Outcome::Uncertain, "pending_address_reconciliation_failed");
        }
    }
    // The same retained-binding policy used by production startup. Retained
    // bindings are observed/preserved; they are not guessed temporary cleanup.
    let observed = match io.native().await {
        Ok(all) => all,
        Err(_) => return Completion::new(Outcome::Uncertain, "retained_observation_unavailable"),
    };
    for (subnet, row) in config.get().adopted_meta {
        let Some(native) = observed
            .iter()
            .find(|n| Some(&n.identity().mac) == row.adapter_mac.as_ref())
        else {
            return Completion::new(Outcome::Uncertain, "retained_identity_conflict");
        };
        let iface = io.descriptor(native);
        let action = super::binding_action(
            &subnet,
            &row,
            iface.as_ref(),
            config.get_network_mode(),
            &Ok(native.dhcp),
            &[],
        );
        let ips = native.ips.clone();
        let updated = super::apply_binding(
            &AddressOps(io.as_ref(), Some(native)),
            row,
            action,
            iface.as_ref(),
            || async { Ok(ips) },
        )
        .await;
        if updated.last_error.is_some() || !updated.applied {
            return Completion::new(Outcome::Uncertain, "retained_binding_unresolved");
        }
        io.persist_binding(&config, &subnet, updated).unwrap();
    }
    Completion::new(Outcome::Completed, "native_effects_reconciled")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "A-S2 actual Tokio caller abort after contained native dispatch"]
async fn qualify_caller_abort_retains_completion_and_barrier() {
    let mut observations = vec![];
    for observation_available in [false, true] {
        let io = FakeAddressIo::new(&[]);
        let config = config_for(&io);
        let executor = new_executor();
        assert!(matches!(
            executor.submit(|_| async { unreachable!() }),
            Err(AdmissionError::ReconciliationRequired)
        ));
        initial_observation(&executor).await;
        let (dispatched, ready) = tokio::sync::oneshot::channel();
        let running_executor = executor.clone();
        let effects = io.clone();
        let owned_config = config.clone();
        let native_result = Arc::new(std::sync::Mutex::new(None));
        let runner_record = native_result.clone();
        let caller = tokio::spawn(async move {
            let ticket = running_executor.submit_managed(move |cancel| async move {
                let native = effects.table.lock().unwrap()[0].clone();
                // Simulate a provider applying an address before reporting an
                // error. PendingAdoptOps retains the existing durable intent.
                *effects.effect.lock().unwrap()=Effect::ErrorAfter;
                let ops = PendingAdoptOps {config:owned_config.as_ref(),adapter_mac:&native.mac,ops:AddressOps(effects.as_ref(),Some(&native)),persist: |_| Ok(())};
                assert!(ops.add(&native.alias,"192.0.2.254".parse().unwrap(),"255.255.255.0").await.is_err());
                let process = tokio::task::spawn_blocking(move || NativeProcessRunner::run(QualificationOperation::ChildTree,cancel,Duration::from_secs(15),Some(dispatched))).await.unwrap().unwrap();
                *runner_record.lock().unwrap()=Some(json!({"termination":format!("{:?}",process.termination),"elapsed_ms":process.elapsed.as_millis(),"runner_deadline_ms":15000,"all_observed_children_exited":process.observed_tree_exited}));
                match effects.native().await {
                    Ok(all) if all[0].ips.iter().any(|a| a.address == "192.0.2.254") => Completion::new(Outcome::Completed,"provider_effect_observed_despite_canceled_reply"),
                    _ => Completion::new(Outcome::Uncertain,"provider_effect_cannot_be_observed"),
                }
            }).unwrap();
            ticket.wait().await.unwrap()
        });
        let pid = tokio::time::timeout(Duration::from_secs(10), ready)
            .await
            .unwrap()
            .unwrap();
        io.fail_read
            .store(!observation_available, Ordering::Relaxed);
        caller.abort(); // The actual requesting task, not the runner timeout.
        assert!(caller.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(8), executor.wait_terminal())
            .await
            .unwrap();
        let (id, completion) = executor.retained().expect("lost reply lost completion");
        let expected = if observation_available {
            Outcome::Completed
        } else {
            Outcome::Uncertain
        };
        assert_eq!(completion.outcome, expected);
        assert!(matches!(
            executor.submit(|_| async { unreachable!() }),
            Err(AdmissionError::ReconciliationRequired)
        ));
        assert_eq!(io.writes.lock().unwrap().len(), 1);
        assert_eq!(config.get().pending_addresses.len(), 1);
        if !observation_available {
            assert_eq!(
                executor.acknowledge(id),
                Err(AdmissionError::ReconciliationRequired)
            );
            let c = config.clone();
            let effects = io.clone();
            let failed = executor
                .reconcile(move |_| reconcile_existing(c, effects))
                .unwrap()
                .wait()
                .await
                .unwrap();
            assert_eq!(failed.outcome, Outcome::Uncertain);
            assert!(matches!(
                executor.submit(|_| async { unreachable!() }),
                Err(AdmissionError::ReconciliationRequired)
            ));
            assert_eq!(io.writes.lock().unwrap().len(), 1);
        }
        io.fail_read.store(false, Ordering::Relaxed);
        *io.effect.lock().unwrap() = Effect::Apply;
        let c = config.clone();
        let effects = io.clone();
        let recovered = executor
            .reconcile(move |_| reconcile_existing(c, effects))
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(recovered.outcome, Outcome::Completed);
        assert!(config.get().pending_addresses.is_empty());
        assert!(io.table.lock().unwrap()[0].ips.is_empty());
        let later = executor
            .submit(|_| async { Completion::new(Outcome::Canceled, "no_effects_accounted") })
            .unwrap();
        let later_id = later.id;
        assert_eq!(later.wait().await.unwrap().outcome, Outcome::Canceled);
        executor.acknowledge(later_id).unwrap();
        let failure = executor
            .submit(|_| async {
                Completion::new(Outcome::Failed, "required_step_failed_without_effect")
            })
            .unwrap();
        let failure_id = failure.id;
        assert_eq!(failure.wait().await.unwrap().outcome, Outcome::Failed);
        executor.acknowledge(failure_id).unwrap();
        executor.shutdown().await;
        assert!(matches!(
            executor.submit(|_| async { unreachable!() }),
            Err(AdmissionError::ShuttingDown)
        ));
        let process = native_result.lock().unwrap().clone().unwrap();
        assert_eq!(process["termination"], "Canceled");
        assert!(process["elapsed_ms"].as_u64().unwrap() < 15000);
        observations.push(json!({"observation_available":observation_available,"dispatched_pid":pid,"actual_requesting_task_aborted":true,"retained_outcome":format!("{:?}",expected),"conflicting_write_refused":true,"runner":process,"pending_intent_retained_until_reconciliation":true,"after_reconciliation_admission_restored":true,"shutdown_drained":true}));
    }
    record(
        "caller-abort-and-barrier",
        json!({"gate":"A-S2","cases":observations,"bounded_retained_completions":1,"admission_queue":0,"address_seams":"existing FakeAddressIo, AddressOps, PendingAdoptOps and AppConfig serialization","network_or_firewall_mutation":false}),
    );
}

fn child(mode: &str, dir: &Path, nonce: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "network::native_qualification::owner_child",
            "--nocapture",
        ])
        .env("POCKETSTREAM_OWNER_PROOF_MODE", mode)
        .env("POCKETSTREAM_OWNER_PROOF_DIR", dir)
        .env("POCKETSTREAM_OWNER_PROOF_NONCE", nonce)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
struct SoleFixtureOwner(Child);
impl Drop for SoleFixtureOwner {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn verify_namespace_and_security_refusals() {
    use super::native_runner::{wide, Handle};
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_INVALID_HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexExW};
    let nonce = format!("{:032x}", rand::random::<u128>());
    let name = wide(std::ffi::OsStr::new(&format!(
        "Global\\PocketStream.Qualification.{nonce}.PocketStream.Desktop.HostOwner.v2"
    )));
    let event =
        Handle::checked(unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) }).unwrap();
    assert!(matches!(
        MachineGuard::acquire_fixture(&nonce, Role::Host, Duration::ZERO),
        Err(OwnershipError::NamespaceOrSecurity(ERROR_INVALID_HANDLE))
    ));
    drop(event);
    // A colliding mutex with an Everyone grant is not accepted as ours.
    let mut sd = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(std::ffi::OsStr::new(
                    "D:P(A;;0x001f0001;;;WD)S:(ML;;NW;;;ME)",
                ))
                .as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        },
        0
    );
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let foreign =
        Handle::checked(unsafe { CreateMutexExW(&security, name.as_ptr(), 0, 0x00120001) })
            .unwrap();
    unsafe { LocalFree(sd) };
    assert!(matches!(
        MachineGuard::acquire_fixture(&nonce, Role::Host, Duration::ZERO),
        Err(OwnershipError::DescriptorMismatch { .. })
    ));
    drop(foreign);
}
fn read_when_ready(path: &Path) -> Value {
    let start = Instant::now();
    loop {
        if let Ok(bytes) = fs::read(path) {
            if let Ok(value) = serde_json::from_slice(&bytes) {
                return value;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(12),
            "child did not publish {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn write_json(path: &Path, value: Value) {
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

#[test]
#[ignore = "A-S4 two processes and sole-owner crash; private nonce namespace"]
fn qualify_two_owners_and_lone_crash_recovery() {
    verify_namespace_and_security_refusals();
    assert_eq!(
        Role::Host.name(),
        "Global\\PocketStream.Desktop.HostOwner.v2"
    );
    assert_eq!(
        Role::Installation.name(),
        "Global\\PocketStream.Desktop.InstallGate.v2"
    );
    let dir = tempfile::tempdir_in(evidence_root()).unwrap();
    let nonce = format!("{:032x}", rand::random::<u128>());
    let mut owner = SoleFixtureOwner(child("hold", dir.path(), &nonce));
    let ready_path = dir.path().join("owner-ready.json");
    let waiting = Instant::now();
    let ready = loop {
        if let Ok(bytes) = fs::read(&ready_path) {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                break value;
            }
        }
        if let Some(status) = owner.0.try_wait().unwrap() {
            let mut diagnostic = String::new();
            std::io::Read::read_to_string(owner.0.stderr.as_mut().unwrap(), &mut diagnostic)
                .unwrap();
            panic!("fixture owner exited {status}: {diagnostic}");
        }
        assert!(
            waiting.elapsed() < Duration::from_secs(12),
            "fixture owner did not become ready"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(ready["ownership_acquired_before_initialization"], true);
    let config_before = fs::read(dir.path().join("config.toml")).unwrap();
    let os_before = fs::read(dir.path().join("fake-native-addresses.json")).unwrap();
    let contender = child("contend", dir.path(), &nonce)
        .wait_with_output()
        .unwrap();
    assert!(contender.status.success(), "contender child failed");
    let busy = read_when_ready(&dir.path().join("contender.json"));
    assert_eq!(busy["busy"], true);
    assert_eq!(busy["initialized"], false);
    assert_eq!(
        fs::read(dir.path().join("config.toml")).unwrap(),
        config_before
    );
    assert_eq!(
        fs::read(dir.path().join("fake-native-addresses.json")).unwrap(),
        os_before
    );
    // The contender has exited and the parent has never opened a mutex
    // handle. Killing this sole private fixture owner destroys the object.
    owner.0.kill().unwrap();
    assert!(!owner.0.wait().unwrap().success());
    let replacement = child("recover", dir.path(), &nonce)
        .wait_with_output()
        .unwrap();
    assert!(
        replacement.status.success(),
        "recovery child failed: {}",
        String::from_utf8_lossy(&replacement.stderr)
    );
    let recovered = read_when_ready(&dir.path().join("recovered.json"));
    assert_eq!(recovered["acquisition"]["newly_created"], true);
    assert_eq!(recovered["acquisition"]["abandoned"], false);
    assert_eq!(recovered["writes_before_reconciliation"], 0);
    assert_eq!(recovered["unknown_observation_blocked"], true);
    assert_eq!(recovered["identity_conflict_blocked"], true);
    assert_eq!(recovered["retained_binding_preserved"], true);
    assert_eq!(recovered["pending_reconciled_before_admission"], true);
    record(
        "two-owners-and-lone-crash",
        json!({"gate":"A-S4 ownership","owner":ready,"contender":busy,"restarted":recovered,"sole_owner_crash":true,"no_parent_or_contender_mutex_handles_at_crash":true,"wrong_namespace_and_foreign_dacl_refused":true,"ordinary_interactive_rights":"SYNCHRONIZE | MUTEX_MODIFY_STATE | READ_CONTROL; explicit Medium label; exact ACL/label readback (SACL AI bookkeeping normalized)","cross_account_or_cross_logon_execution":"not exercised by this same-account fixture","production_startup_integration":"deferred until prerequisite review","network_or_firewall_mutation":false}),
    );
}

#[test]
#[ignore = "internal subprocess of A-S4; not a standalone qualification"]
fn owner_child() {
    let Ok(mode) = std::env::var("POCKETSTREAM_OWNER_PROOF_MODE") else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os("POCKETSTREAM_OWNER_PROOF_DIR").unwrap());
    let nonce = std::env::var("POCKETSTREAM_OWNER_PROOF_NONCE").unwrap();
    let guard = MachineGuard::acquire_fixture(&nonce, Role::Host, Duration::from_millis(100));
    if mode == "contend" {
        assert!(
            matches!(guard, Err(OwnershipError::Busy)),
            "contender not Busy"
        );
        write_json(
            &dir.join("contender.json"),
            json!({"pid":std::process::id(),"busy":true,"initialized":false}),
        );
        return;
    }
    let guard = guard.unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        if mode=="hold" {
            let io=FakeAddressIo::new(&["192.0.2.100"]);
            let config=config_for(&io);
            let native=io.table.lock().unwrap()[0].clone();
            config.set_temporary_test_binding("192.0.2.0/24",crate::config::AdoptedMeta {adapter_mac:Some(native.mac.clone()),prefix:Some(24),address:Some("192.0.2.100".into()),applied:true,..Default::default()}).unwrap();
            let ops=PendingAdoptOps {config:config.as_ref(),adapter_mac:&native.mac,ops:AddressOps(io.as_ref(),Some(&native)),persist: |_| Ok(())};
            ops.add(&native.alias,"192.0.2.254".parse().unwrap(),"255.255.255.0").await.unwrap();
            fs::write(dir.join("config.toml"),crate::config::test_support::serialize_for_test(&config.get())).unwrap();
            write_json(&dir.join("fake-native-addresses.json"),json!(["192.0.2.100","192.0.2.254"]));
            write_json(&dir.join("owner-ready.json"),json!({"pid":std::process::id(),"ownership_acquired_before_initialization":true,"acquisition":guard.acquisition,"pending_addresses":config.get().pending_addresses.len()}));
            loop {std::thread::sleep(Duration::from_millis(100));}
        }
        assert_eq!(mode,"recover");
        let saved=fs::read_to_string(dir.join("config.toml")).unwrap();
        let config=Arc::new(AppConfig::temporary_test_config(crate::config::test_support::parse_for_test(&saved).unwrap()));
        let ips:Vec<String>=serde_json::from_slice(&fs::read(dir.join("fake-native-addresses.json")).unwrap()).unwrap();
        let io=FakeAddressIo::new(&ips.iter().map(String::as_str).collect::<Vec<_>>());
        let executor=new_executor();
        assert!(matches!(executor.submit(|_| async {unreachable!()}),Err(AdmissionError::ReconciliationRequired)));
        io.fail_read.store(true,Ordering::Relaxed);
        let c=config.clone();let effects=io.clone();
        assert_eq!(executor.reconcile(move |_| reconcile_existing(c,effects)).unwrap().wait().await.unwrap().outcome,Outcome::Uncertain);
        assert!(matches!(executor.submit(|_| async {unreachable!()}),Err(AdmissionError::ReconciliationRequired)));
        assert!(io.writes.lock().unwrap().is_empty());
        io.fail_read.store(false,Ordering::Relaxed);
        let mac=io.table.lock().unwrap()[0].mac.clone();
        io.table.lock().unwrap()[0].mac="40:cd:3a:00:00:02".into();
        let c=config.clone();let effects=io.clone();
        assert_eq!(executor.reconcile(move |_| reconcile_existing(c,effects)).unwrap().wait().await.unwrap().outcome,Outcome::Uncertain);
        assert!(matches!(executor.submit(|_| async {unreachable!()}),Err(AdmissionError::ReconciliationRequired)));
        assert!(io.writes.lock().unwrap().is_empty());
        io.table.lock().unwrap()[0].mac=mac;
        let c=config.clone();let effects=io.clone();
        assert_eq!(executor.reconcile(move |_| reconcile_existing(c,effects)).unwrap().wait().await.unwrap().outcome,Outcome::Completed);
        assert!(config.get().pending_addresses.is_empty());
        assert_eq!(io.table.lock().unwrap()[0].ips.len(),1);
        assert_eq!(io.table.lock().unwrap()[0].ips[0].address,"192.0.2.100");
        let admitted=executor.submit(|_| async {Completion::new(Outcome::Completed,"conflicting_write_admitted_after_reconciliation")}).unwrap();
        let id=admitted.id;
        admitted.wait().await.unwrap();executor.acknowledge(id).unwrap();
        executor.shutdown().await;
        write_json(&dir.join("recovered.json"),json!({"pid":std::process::id(),"acquisition":guard.acquisition,"writes_before_reconciliation":0,"unknown_observation_blocked":true,"identity_conflict_blocked":true,"retained_binding_preserved":true,"pending_reconciled_before_admission":true,"fake_writes":*io.writes.lock().unwrap(),"executor_drained_before_owner_release":true}));
    });
    drop(guard);
}
