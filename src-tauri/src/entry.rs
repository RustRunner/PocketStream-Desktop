//! Fixed maintenance is selected before logging, configuration, Tauri or media.
use crate::network::firewall::Maintenance;

#[derive(Debug)]
enum Entry {
    Host,
    Maintenance(Maintenance),
}

fn parse(args: &[String]) -> Result<Entry, &'static str> {
    match args {
        [] => Ok(Entry::Host),
        [flag, mode] if flag == "--firewall-maintenance" => match mode.as_str() {
            "install" => Ok(Entry::Maintenance(Maintenance::Install)),
            "uninstall" => Ok(Entry::Maintenance(Maintenance::Uninstall)),
            _ => Err("Expected fixed firewall maintenance mode install or uninstall"),
        },
        _ => Err("Unknown or malformed PocketStream arguments"),
    }
}

pub(crate) fn early_exit(args: Vec<String>) -> Option<i32> {
    let entry = match parse(&args) {
        Ok(entry) => entry,
        Err(reason) => {
            println!(
                "{}",
                serde_json::json!({"version":2,"state":"failed","stage":"arguments","reason":reason})
            );
            return Some(64);
        }
    };
    let Entry::Maintenance(mode) = entry else {
        return None;
    };
    #[cfg(windows)]
    {
        use crate::network::{
            firewall,
            host_owner::{MachineGuard, Role},
        };
        use std::time::Duration;
        let root = match crate::maintenance::protected_root() {
            Ok(root) => root,
            Err(reason) => {
                println!(
                    "{}",
                    serde_json::json!({"version":2,"state":"failed","stage":"maintenance_preflight","reason":reason})
                );
                return Some(77);
            }
        };
        // The elevated installer already holds InstallGate. Acquiring it here
        // would deadlock the parent/child transaction.
        let _owner = match MachineGuard::acquire(Role::Host, Duration::from_secs(5)) {
            Ok(owner) => owner,
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"version":2,"state":"failed","stage":"ownership","reason":format!("{error:?}").chars().take(192).collect::<String>()})
                );
                return Some(73);
            }
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let journal_name = format!(
            "firewall-maintenance-{}-{timestamp}.json",
            std::process::id()
        );
        let mut journal = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(&journal_name))
        {
            Ok(journal) => journal,
            Err(_) => {
                println!(
                    "{}",
                    serde_json::json!({"version":2,"state":"failed","stage":"diagnostics","reason":"Cannot reserve protected maintenance diagnostics"})
                );
                return Some(74);
            }
        };
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return Some(70),
        };
        let outcome = runtime.block_on(firewall::maintenance(mode));
        runtime.block_on(crate::network::native_operations::shutdown());
        let observation = firewall::MAINTENANCE_OBSERVATION.lock().unwrap().take();
        let record = serde_json::json!({"version":2,"operation":mode,"outcome":outcome,"observation":observation});
        use std::io::Write;
        let persisted = serde_json::to_vec(&record)
            .ok()
            .filter(|bytes| bytes.len() <= 65536)
            .is_some_and(|bytes| {
                journal
                    .write_all(&bytes)
                    .and_then(|_| journal.sync_all())
                    .is_ok()
            });
        if !persisted {
            println!(
                "{}",
                serde_json::json!({"version":2,"state":"failed","stage":"diagnostics","reason":"Maintenance result could not be persisted; native effects require review"})
            );
            return Some(74);
        }
        println!(
            "{}",
            serde_json::json!({"version":2,"operation":mode,"outcome":outcome,"journal":journal_name})
        );
        Some(if matches!(outcome, firewall::FirewallOutcome::Inactive) {
            0
        } else {
            71
        })
    }
    #[cfg(not(windows))]
    {
        let _ = mode;
        Some(69)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maintenance_has_no_path_script_or_gui_fallback() {
        for args in [
            vec!["--firewall-maintenance"],
            vec!["--firewall-maintenance", "repair"],
            vec!["--firewall-maintenance", "install", "C:\\other.exe"],
            vec!["--unknown"],
        ] {
            assert!(parse(&args.into_iter().map(str::to_string).collect::<Vec<_>>()).is_err());
        }
        assert!(matches!(parse(&[]), Ok(Entry::Host)));
        assert!(matches!(
            parse(&["--firewall-maintenance".into(), "install".into()]),
            Ok(Entry::Maintenance(Maintenance::Install))
        ));
    }
}
