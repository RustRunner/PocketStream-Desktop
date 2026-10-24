use crate::error::AppError;

/// Assign a static IP address to a network interface.
///
/// Preserve all other observed addresses: ownership cannot be inferred
/// from enumeration order, and user-managed secondaries must survive Apply.
///
/// Platform-specific implementation:
/// - Windows: uses `netsh interface ip set address`
/// - Linux: uses `ip addr` commands
pub(crate) async fn assign_static_ip(
    interface: &str,
    ip: &str,
    subnet_mask: &str,
    gateway: Option<&str>,
    expected: &super::interface::NativeIdentity,
) -> Result<(), AppError> {
    #[cfg(not(windows))]
    let _ = expected;
    super::interface::validate_interface_name(interface).await?;
    validate_ip(ip)?;
    validate_ip(subnet_mask)?;
    if let Some(gw) = gateway {
        validate_ip(gw)?;
    }

    #[cfg(target_os = "windows")]
    {
        assign_windows(interface, ip, subnet_mask, gateway, expected).await
    }

    #[cfg(target_os = "linux")]
    {
        assign_linux(interface, ip, subnet_mask, gateway).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(AppError::Network("Unsupported platform".into()))
    }
}

#[cfg(target_os = "windows")]
async fn assign_windows(
    interface: &str,
    ip: &str,
    subnet_mask: &str,
    gateway: Option<&str>,
    expected: &super::interface::NativeIdentity,
) -> Result<(), AppError> {
    assign_windows_with(&WindowsIpOps, interface, ip, subnet_mask, gateway, expected).await
}

#[cfg(windows)]
trait StaticIpOps {
    async fn snapshot(&self, interface: &str) -> Result<super::interface::NativeAdapter, AppError>;
    async fn apply(
        &self,
        adapter: &super::interface::NativeAdapter,
        ip: &str,
        prefix: u8,
    ) -> Result<(), AppError>;
}

#[cfg(windows)]
struct WindowsIpOps;
#[cfg(windows)]
impl StaticIpOps for WindowsIpOps {
    async fn snapshot(&self, interface: &str) -> Result<super::interface::NativeAdapter, AppError> {
        let all = super::interface::read_native().await?;
        Ok(super::interface::native_by_alias(&all, interface)?.clone())
    }
    async fn apply(
        &self,
        adapter: &super::interface::NativeAdapter,
        ip: &str,
        prefix: u8,
    ) -> Result<(), AppError> {
        super::native_operations::execute(super::native_operations::Operation::static_address(
            adapter, ip, prefix,
        )?)
        .await
    }
}
#[cfg(windows)]
async fn assign_windows_with(
    ops: &impl StaticIpOps,
    interface: &str,
    ip: &str,
    mask: &str,
    gateway: Option<&str>,
    expected: &super::interface::NativeIdentity,
) -> Result<(), AppError> {
    let prefix = mask_to_prefix(mask)?;
    let address = ip
        .parse()
        .map_err(|_| AppError::Network("Invalid static address".into()))?;
    super::native_operations::validate_host(address, prefix)?;
    let before = ops.snapshot(interface).await?;
    if before.identity() != *expected {
        return Err(AppError::Network(
            "Selected adapter changed before primary write".into(),
        ));
    }
    // A never accepts a new caller-selected gateway. The fixed native policy
    // re-snapshots and preserves the compatible actual gateway in its worker.
    if gateway.is_some_and(|gw| !before.gateways.iter().any(|native| native == gw)) {
        return Err(AppError::Network(
            "Gateway changes are unsupported; preserve the current Windows gateway".into(),
        ));
    }
    if before.gateways.len() > 1
        || before.gateways.iter().any(|gateway| {
            gateway.parse::<std::net::Ipv4Addr>().map_or(true, |gw| {
                gw == address
                    || !ipnetwork::Ipv4Network::new(address, prefix)
                        .unwrap()
                        .contains(gw)
            })
        })
    {
        return Err(AppError::Network(
            "Current default gateway cannot be preserved on the requested subnet".into(),
        ));
    }
    ops.apply(&before, ip, prefix).await
}

/// Convert a CIDR prefix length to a dotted subnet mask.
pub(crate) fn prefix_to_mask(prefix: u8) -> String {
    // Both ends must be special-cased: `u32 << 32` (prefix 0) and
    // `u32 << (32 - prefix)` for prefix > 32 are shift overflows that
    // panic in debug and wrap in release.
    let bits: u32 = match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    };
    let o = bits.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

#[cfg(target_os = "linux")]
async fn assign_linux(
    interface: &str,
    ip: &str,
    subnet_mask: &str,
    gateway: Option<&str>,
) -> Result<(), AppError> {
    let prefix = mask_to_prefix(subnet_mask)?;
    let cidr = format!("{}/{}", ip, prefix);

    // Flush existing addresses
    run_command("ip", &["addr", "flush", "dev", interface]).await?;

    // Add new address
    run_command("ip", &["addr", "add", &cidr, "dev", interface]).await?;

    // Set link up
    run_command("ip", &["link", "set", interface, "up"]).await?;

    // Add default gateway if provided
    if let Some(gw) = gateway {
        // Ignore error if route already exists
        let _ = run_command(
            "ip",
            &["route", "add", "default", "via", gw, "dev", interface],
        )
        .await;
    }

    Ok(())
}

/// Bounded timeout for the IP-configuration commands.
/// `New-NetIPAddress` and `netsh delete address` normally return in well
/// under a second; 30 s is a generous ceiling that turns a genuine hang
/// into an error instead of a wedged adoption.
#[cfg(not(windows))]
const IP_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Run a command with the default `IP_CMD_TIMEOUT` bound. Delegates to
/// `run_command_killable` so every caller inherits kill-on-drop and the
/// timeout — a hung child surfaces as an error instead of wedging the
/// caller and leaking the process.
#[cfg(not(windows))]
pub(crate) async fn run_command(program: &str, args: &[&str]) -> Result<String, AppError> {
    run_command_killable(program, args, IP_CMD_TIMEOUT).await
}

/// Like `run_command` but sets `kill_on_drop(true)` and bounds the call
/// with a timeout. Used by the auto-adopt IP mutations (add/remove
/// secondary IP): when the adopting task's future is dropped — a bounded
/// adoption timeout, or a discovery stop that aborts the task — the
/// in-flight child is killed instead of running on to mutate the adapter
/// after reconciliation has already swept, which would be an untracked-IP
/// leak the pending registry could not catch. The timeout is a
/// complementary guard against a single hung invocation.
#[cfg(not(windows))]
pub(crate) async fn run_command_killable(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> Result<String, AppError> {
    let fut = super::async_cmd(program)
        .args(args)
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| {
            AppError::Network(format!(
                "{} timed out after {}s",
                program,
                timeout.as_secs()
            ))
        })?
        .map_err(|e| AppError::Network(format!("Failed to run {}: {}", program, e)))?;
    process_command_output(program, output)
}

#[cfg(not(windows))]
fn process_command_output(program: &str, output: std::process::Output) -> Result<String, AppError> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let msg = if stderr.trim().is_empty() {
            stdout
        } else {
            stderr
        };
        return Err(AppError::Network(format!(
            "{} failed: {}",
            program,
            msg.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn validate_ip(ip: &str) -> Result<(), AppError> {
    ip.parse::<std::net::Ipv4Addr>()
        .map_err(|_| AppError::Network(format!("Invalid IP address: {}", ip)))?;
    Ok(())
}

pub(crate) fn mask_to_prefix(mask: &str) -> Result<u8, AppError> {
    let addr: std::net::Ipv4Addr = mask
        .parse()
        .map_err(|_| AppError::Network(format!("Invalid subnet mask: {}", mask)))?;
    let bits: u32 = u32::from(addr);
    let prefix = bits.count_ones() as u8;
    if bits
        != if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    {
        return Err(AppError::Network("Subnet mask must be contiguous".into()));
    }
    Ok(prefix)
}

/// Add a secondary IP address to an interface (preserves existing IPs).
///
/// Windows uses `New-NetIPAddress`, not `netsh interface ip add address`:
/// New-NetIPAddress disables DHCP when adding a static address, so every
/// secondary add requires a fresh, successful static-state observation.
pub async fn add_secondary_ip(interface: &str, ip: &str, mask: &str) -> Result<(), AppError> {
    super::interface::validate_interface_name(interface).await?;
    validate_ip(ip)?;
    validate_ip(mask)?;
    let prefix = mask_to_prefix(mask)?;
    if !super::interface::get_by_name(interface).await?.is_up {
        return Err(AppError::Network("selected adapter unavailable".into()));
    }
    if get_dhcp_state(interface).await? {
        return Err(AppError::Network(
            "adapter is DHCP; switch to a static mode before adding an address".into(),
        ));
    }

    #[cfg(windows)]
    {
        let all = super::interface::read_native().await?;
        let adapter = super::interface::native_by_alias(&all, interface)?;
        super::native_operations::execute(super::native_operations::Operation::address(
            adapter, ip, prefix, true, true,
        )?)
        .await?;
    }

    #[cfg(target_os = "linux")]
    {
        let cidr = format!("{}/{}", ip, prefix);
        run_command_killable(
            "ip",
            &["addr", "add", &cidr, "dev", interface],
            IP_CMD_TIMEOUT,
        )
        .await?;
    }

    Ok(())
}

/// Switch the interface to DHCP mode (clears static IPs, enables DHCP for
/// IPv4 and DNS, renews the lease). Requires admin; same fast-path-then-
/// elevate pattern as `adapter_refresh::hard_refresh_windows`.
pub async fn set_dhcp(interface: &str) -> Result<(), AppError> {
    super::interface::validate_interface_name(interface).await?;

    #[cfg(target_os = "windows")]
    {
        set_dhcp_windows(interface).await
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(AppError::Network(
            "DHCP toggle is only implemented on Windows".into(),
        ))
    }
}

#[cfg(windows)]
async fn set_dhcp_windows(interface: &str) -> Result<(), AppError> {
    let all = super::interface::read_native().await?;
    let adapter = super::interface::native_by_alias(&all, interface)?;
    super::native_operations::execute(super::native_operations::Operation::dhcp(adapter)?).await
}

/// Read whether the interface is currently in DHCP mode for IPv4. No admin
/// required. Called by the dialog at open time to position the mode toggle.
pub async fn get_dhcp_state(interface: &str) -> Result<bool, AppError> {
    #[cfg(target_os = "windows")]
    {
        super::interface::native_dhcp_state(interface).await
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = interface;
        Err(AppError::Network(
            "DHCP state query is only implemented on Windows".into(),
        ))
    }
}

#[cfg(test)]
fn parse_dhcp_state(output: &str) -> Result<bool, AppError> {
    match output.trim().to_ascii_lowercase().as_str() {
        "enabled" => Ok(true),
        "disabled" => Ok(false),
        _ => Err(AppError::Network(
            "DHCP state query returned an unknown or ambiguous value".into(),
        )),
    }
}

/// Remove a secondary IP address from an interface.
/// Operation writers accept a just-validated native observation. The public
/// legacy entry points retain their own native validation for other callers.
pub(super) async fn add_native_address(
    adapter: &super::interface::NativeAdapter,
    ip: &str,
    mask: &str,
) -> Result<(), AppError> {
    validate_ip(ip)?;
    let prefix = mask_to_prefix(mask)?;
    validate_native_writer(adapter)?;
    if !adapter.is_up {
        return Err(AppError::Network(
            "Selected Ethernet adapter is disconnected".into(),
        ));
    }
    if adapter.dhcp {
        return Err(AppError::Network("adapter is DHCP".into()));
    }
    #[cfg(windows)]
    {
        super::native_operations::execute(super::native_operations::Operation::address(
            adapter, ip, prefix, true, false,
        )?)
        .await?;
    }
    #[cfg(not(windows))]
    {
        let _ = prefix;
        Err(AppError::Network("Native writes require Windows".into()))
    }
    #[cfg(windows)]
    {
        Ok(())
    }
}
fn validate_native_writer(adapter: &super::interface::NativeAdapter) -> Result<(), AppError> {
    if adapter.index == 0 || adapter.guid.is_empty() || adapter.alias.is_empty() {
        return Err(AppError::Network(
            "Selected adapter unavailable or unqualified".into(),
        ));
    }
    Ok(())
}
pub(super) async fn remove_native_address(
    adapter: &super::interface::NativeAdapter,
    ip: &str,
) -> Result<(), AppError> {
    validate_ip(ip)?;
    validate_native_writer(adapter)?;
    #[cfg(windows)]
    {
        // Removal uses the exact observed prefix, including existing APIPA.
        let prefix = adapter
            .ips
            .iter()
            .find(|a| a.address == ip)
            .map(|a| a.prefix)
            .ok_or_else(|| {
                AppError::Network(
                    "Address removal requires a current address/prefix observation".into(),
                )
            })?;
        super::native_operations::execute(super::native_operations::Operation::address(
            adapter, ip, prefix, false, false,
        )?)
        .await
    }
    #[cfg(not(windows))]
    {
        Err(AppError::Network("Native writes require Windows".into()))
    }
}

pub async fn remove_secondary_ip(interface: &str, ip: &str) -> Result<(), AppError> {
    super::interface::validate_interface_name(interface).await?;
    validate_ip(ip)?;

    #[cfg(windows)]
    {
        let all = super::interface::read_native().await?;
        let adapter = super::interface::native_by_alias(&all, interface)?;
        // A successful absence is idempotent; a failed query never becomes absence.
        if adapter.ips.iter().any(|a| a.address == ip) {
            remove_native_address(adapter, ip).await?;
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Find the prefix for this IP — default to /24
        let cidr = format!("{}/24", ip);
        run_command_killable(
            "ip",
            &["addr", "del", &cidr, "dev", interface],
            IP_CMD_TIMEOUT,
        )
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    struct StaticOps {
        metadata: super::super::interface::NativeAdapter,
        native_fails: bool,
        commands: std::sync::Mutex<Vec<Vec<String>>>,
    }

    #[cfg(target_os = "windows")]
    impl StaticIpOps for StaticOps {
        async fn snapshot(
            &self,
            _: &str,
        ) -> Result<super::super::interface::NativeAdapter, AppError> {
            if self.native_fails {
                Err(AppError::Network(
                    "GetAdaptersAddresses failed with code 8".into(),
                ))
            } else {
                Ok(self.metadata.clone())
            }
        }
        async fn apply(
            &self,
            _adapter: &super::super::interface::NativeAdapter,
            ip: &str,
            prefix: u8,
        ) -> Result<(), AppError> {
            self.commands
                .lock()
                .unwrap()
                .push(vec![ip.into(), prefix.to_string()]);
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn static_apply_requires_native_snapshot_before_replacing_addresses() {
        use super::super::interface::{IpInfo, NativeAdapter};
        for native_fails in [true, false] {
            let ops = StaticOps {
                metadata: NativeAdapter {
                    alias: "Ethernet".into(),
                    index: 7,
                    guid: "guid-a".into(),
                    dhcp: false,
                    gateways: vec![],
                    mac: "40:cd:3a:00:00:01".into(),
                    is_up: true,

                    ips: ["192.0.2.20", "198.51.100.99"]
                        .into_iter()
                        .map(|address| IpInfo {
                            address: address.into(),
                            prefix: 24,
                            subnet: String::new(),
                        })
                        .collect(),
                },
                native_fails,
                commands: Default::default(),
            };
            let result = assign_windows_with(
                &ops,
                "Ethernet",
                "192.0.2.20",
                "255.255.255.0",
                None,
                &ops.metadata.identity(),
            )
            .await;
            let commands = ops.commands.lock().unwrap();
            if native_fails {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("GetAdaptersAddresses failed"));
                assert!(
                    commands.is_empty(),
                    "unknown addresses must prevent netsh set"
                );
            } else {
                result.unwrap();
                assert_eq!(*commands, vec![vec!["192.0.2.20", "24"]]);
            }
        }
    }

    #[test]
    fn unknown_dhcp_output_never_authorizes_a_static_write() {
        assert!(parse_dhcp_state(" Enabled\r\n").unwrap());
        assert!(!parse_dhcp_state("Disabled").unwrap());
        for output in ["", "unknown", "Enabled\nDisabled", "False"] {
            assert!(parse_dhcp_state(output).is_err());
        }
        assert!(mask_to_prefix("255.0.255.0").is_err());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn primary_writer_rejects_changed_native_identity_before_any_command() {
        let ops = StaticOps {
            metadata: super::super::interface::NativeAdapter {
                alias: "Ethernet".into(),
                guid: "new-guid".into(),
                index: 7,
                is_up: true,
                ..Default::default()
            },
            native_fails: false,
            commands: Default::default(),
        };
        let mut expected = ops.metadata.identity();
        expected.guid = "old-guid".into();
        assert!(assign_windows_with(
            &ops,
            "Ethernet",
            "192.0.2.10",
            "255.255.255.0",
            None,
            &expected
        )
        .await
        .is_err());
        assert!(ops.commands.lock().unwrap().is_empty());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn disconnected_native_writer_allows_removal_validation_but_rejects_addition() {
        let adapter = super::super::interface::NativeAdapter {
            alias: "Ethernet".into(),
            guid: "guid".into(),
            index: 7,
            ..Default::default()
        };
        validate_native_writer(&adapter).unwrap();
        assert!(add_native_address(&adapter, "192.0.2.10", "255.255.255.0")
            .await
            .unwrap_err()
            .to_string()
            .contains("disconnected"));
    }

    // ── validate_ip ─────────────────────────────────────────────────

    #[test]
    fn validate_ip_valid_addresses() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("255.255.255.0").is_ok());
        assert!(validate_ip("0.0.0.0").is_ok());
        assert!(validate_ip("172.16.0.1").is_ok());
    }

    #[test]
    fn validate_ip_invalid_addresses() {
        assert!(validate_ip("").is_err());
        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("256.1.1.1").is_err());
        assert!(validate_ip("192.168.1").is_err());
        assert!(validate_ip("192.168.1.1.1").is_err());
        assert!(validate_ip("::1").is_err()); // IPv6 rejected
    }

    #[test]
    fn validate_ip_error_message() {
        let err = validate_ip("bad").unwrap_err();
        assert!(err.to_string().contains("Invalid IP address"));
        assert!(err.to_string().contains("bad"));
    }

    // ── prefix_to_mask (Windows only) ───────────────────────────────

    #[cfg(target_os = "windows")]
    #[test]
    fn prefix_to_mask_boundaries_do_not_overflow() {
        // /0 and /32 are the shift-overflow edges the old code hit.
        assert_eq!(prefix_to_mask(0), "0.0.0.0");
        assert_eq!(prefix_to_mask(32), "255.255.255.255");
        assert_eq!(prefix_to_mask(24), "255.255.255.0");
        assert_eq!(prefix_to_mask(16), "255.255.0.0");
        assert_eq!(prefix_to_mask(30), "255.255.255.252");
        // Out-of-range clamps to all-ones instead of panicking.
        assert_eq!(prefix_to_mask(40), "255.255.255.255");
    }

    // ── mask_to_prefix (Linux only) ─────────────────────────────────

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::super::*;

        #[test]
        fn mask_to_prefix_common_masks() {
            assert_eq!(mask_to_prefix("255.255.255.0").unwrap(), 24);
            assert_eq!(mask_to_prefix("255.255.0.0").unwrap(), 16);
            assert_eq!(mask_to_prefix("255.0.0.0").unwrap(), 8);
            assert_eq!(mask_to_prefix("255.255.255.255").unwrap(), 32);
            assert_eq!(mask_to_prefix("255.255.255.128").unwrap(), 25);
            assert_eq!(mask_to_prefix("255.255.252.0").unwrap(), 22);
        }

        #[test]
        fn mask_to_prefix_invalid() {
            assert!(mask_to_prefix("not-a-mask").is_err());
        }
    }
}
