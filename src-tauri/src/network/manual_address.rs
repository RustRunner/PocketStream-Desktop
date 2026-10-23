//! Serialized manual address transactions. Metadata and native reads stay
//! separate; the reply is an observation, not an ordering/version protocol.
use super::*;
use crate::config::{AdoptedMeta, AppConfig, BindingDesired, NetworkMode};
use interface::OperationSnapshot;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressOutcome {
    Success,
    Pending,
    Failed,
    Busy,
}

pub enum AddressRequest {
    Add {
        name: String,
        ip: String,
        mask: String,
    },
    RemoveSaved {
        subnet: String,
        hint: Option<String>,
    },
    RemoveManual {
        name: String,
        ip: String,
    },
    RemovePrimary {
        name: String,
        ip: String,
    },
}

#[derive(Debug, Serialize)]
pub struct AddressIdentity {
    pub guid: String,
    pub index: u32,
    pub mac: String,
    pub alias: String,
}

#[derive(Debug, Serialize)]
pub struct AddressView {
    pub selection: AdapterSelection,
    pub identity: Option<AddressIdentity>,
    pub dhcp: Option<bool>,
    pub observation_error: Option<String>,
    pub subnet: Option<String>,
    pub binding: Option<AdoptedMetaView>,
    pub address: String,
    pub prefix: Option<u8>,
    pub mode: NetworkMode,
    pub primary_address: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct AddressReply {
    pub operation: u64,
    pub outcome: AddressOutcome,
    pub reason: Option<String>,
    pub view: AddressView,
}
impl AddressReply {
    #[cfg(test)]
    pub(super) fn legacy_result(self) -> Result<(), AppError> {
        if self.outcome == AddressOutcome::Success {
            Ok(())
        } else {
            Err(AppError::Network(self.reason.unwrap_or_else(|| {
                "Address operation remains pending".into()
            })))
        }
    }
}

struct Transaction {
    trace: AddressTrace,
    mac: Option<String>,
    mode: NetworkMode,
    address: String,
    prefix: Option<u8>,
    subnet: Option<String>,
    row: Option<AdoptedMeta>,
    observed: Option<OperationSnapshot>,
    observation_error: Option<String>,
    intent_saved: bool,
    outcome: AddressOutcome,
    reason: Option<String>,
}
impl Transaction {
    fn reply(
        self,
        manager: &NetworkManager,
        config: &AppConfig,
        pending: &HashSet<String>,
    ) -> AddressReply {
        let (selection, identity, dhcp) = if let Some(snapshot) = &self.observed {
            let mut iface = snapshot.iface.clone();
            iface.ips.retain(|ip| !pending.contains(&ip.address));
            (
                AdapterSelection {
                    selected_mac: self.mac.clone(),
                    interface_index: Some(snapshot.selected.index),
                    adapter: Some(iface),
                    candidates: strip_pending_ips(snapshot.candidates.clone(), pending),
                    selection_required: false,
                },
                Some(AddressIdentity {
                    guid: snapshot.selected.guid.clone(),
                    index: snapshot.selected.index,
                    mac: snapshot.selected.mac.clone(),
                    alias: snapshot.selected.alias.clone(),
                }),
                Some(snapshot.selected.dhcp),
            )
        } else {
            // No empty-success fallback. Unknown addresses are explicitly marked;
            // the consumer retains its last known view until a fresh event/read.
            let cached = manager
                .adapter_selection
                .try_lock()
                .ok()
                .map(|s| s.clone())
                .unwrap_or_default();
            (
                AdapterSelection {
                    selected_mac: self.mac.clone(),
                    adapter: None,
                    interface_index: None,
                    candidates: cached.candidates,
                    selection_required: cached.selection_required,
                },
                None,
                None,
            )
        };
        let binding = self.row.as_ref().map(|row| {
            adoption_meta_view(
                self.subnet.as_deref().unwrap_or(""),
                Some(row),
                None,
                Duration::ZERO,
                None,
            )
        });
        log::info!(
            "event=address_outcome operation={} outcome={:?} reason={}",
            self.trace.id,
            self.outcome,
            log_value(self.reason.as_deref().unwrap_or("none"))
        );
        AddressReply {
            operation: self.trace.id,
            outcome: self.outcome,
            reason: self.reason.clone(),
            view: AddressView {
                selection,
                identity,
                dhcp,
                observation_error: self.observation_error.clone(),
                subnet: self.subnet.clone(),
                binding,
                address: self.address.clone(),
                prefix: self.prefix,
                mode: config.get().network_mode,
                primary_address: self
                    .mac
                    .as_ref()
                    .and_then(|mac| config.get().primary_addresses.get(mac).cloned()),
            },
        }
    }
}

impl NetworkManager {
    /// One admission timeout covers both locks. Guards already acquired, including
    /// the pause guard, are dropped on timeout. Nothing is queued after Busy.
    pub async fn address_operation(
        &self,
        config: &AppConfig,
        request: AddressRequest,
    ) -> AddressReply {
        let removing = !matches!(&request, AddressRequest::Add { .. });
        let primary_removal = matches!(&request, AddressRequest::RemovePrimary { .. });
        let (action, address) = match &request {
            AddressRequest::Add { ip, .. } => ("add", ip.clone()),
            AddressRequest::RemoveManual { ip, .. } | AddressRequest::RemovePrimary { ip, .. } => {
                ("remove_manual", ip.clone())
            }
            AddressRequest::RemoveSaved { subnet, .. } => ("remove_managed", subnet.clone()),
        };
        let fence = self.presence.snapshot().fence;
        let initial = config.get();
        let mut tx = Transaction {
            trace: AddressTrace::new(action, &address),
            mac: initial.selected_adapter_mac,
            mode: initial.network_mode,
            address,
            prefix: None,
            subnet: None,
            row: None,
            observed: None,
            observation_error: None,
            intent_saved: false,
            outcome: AddressOutcome::Failed,
            reason: None,
        };
        let admitted = tokio::time::timeout(Duration::from_secs(10), async {
            let op = self.discovery_op.lock().await;
            let pause = self.pause_addresses();
            let address = self.address_work.lock().await;
            (op, pause, address)
        })
        .await;
        let Ok((_op, _pause, _address)) = admitted else {
            tx.trace.phase("admission_timeout");
            tx.outcome = AddressOutcome::Busy;
            tx.reason = Some("Waiting for current network operation; try again".into());
            tx.observation_error = tx.reason.clone();
            return tx.reply(self, config, &HashSet::new());
        };
        tx.trace.phase("admission");
        let result = match self.validate_operation_context(config, &tx, &fence) {
            Ok(()) => {
                self.run_address_operation(config, request, &fence, &mut tx)
                    .await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            let reason = error.to_string();
            if tx.observed.is_none() {
                tx.observation_error = Some(reason.clone());
            }
            if tx.intent_saved {
                if let (Some(subnet), Some(mut row)) = (tx.subnet.as_deref(), tx.row.clone()) {
                    row.last_error = Some(reason.clone());
                    tx.row = Some(self.publish_binding(config, subnet, row).await);
                    tx.trace.phase("status_save");
                }
                tx.outcome = AddressOutcome::Pending;
            }
            tx.reason = Some(reason);
        }
        if tx.outcome == AddressOutcome::Success
            && removing
            && (primary_removal
                || config
                    .get()
                    .primary_addresses
                    .get(tx.mac.as_deref().unwrap_or(""))
                    .is_some_and(|cidr| cidr.split('/').next() == Some(tx.address.as_str())))
        {
            if let Err(error) =
                self.address_io
                    .persist_primary(config, tx.mac.as_deref().unwrap(), "")
            {
                tx.outcome = AddressOutcome::Failed;
                tx.reason = Some(error.to_string());
            }
        }
        if tx.outcome == AddressOutcome::Success {
            tx.trace.succeeded();
        }
        tx.reply(self, config, &self.pending_ip_strings().await)
    }

    async fn run_address_operation(
        &self,
        config: &AppConfig,
        request: AddressRequest,
        fence: &SweepFence,
        tx: &mut Transaction,
    ) -> Result<(), AppError> {
        let settings = config.get();
        let (add, alias, mask) = match request {
            AddressRequest::Add { name, ip, mask } => {
                ip.parse::<Ipv4Addr>()
                    .map_err(|_| AppError::Network("Invalid IPv4 address".into()))?;
                tx.prefix = Some(ip_config::mask_to_prefix(&mask)?);
                tx.address = ip;
                let rows: Vec<_> = settings
                    .adopted_meta
                    .iter()
                    .filter(|(_, r)| {
                        r.address.as_ref() == Some(&tx.address)
                            && (r.adapter_mac.is_none()
                                || r.adapter_mac.as_deref().and_then(adapter_mac)
                                    == tx.mac.as_deref().and_then(adapter_mac))
                    })
                    .collect();
                if rows.len() > 1 {
                    return Err(AppError::Network(
                        "Saved address ownership is ambiguous; no OS change made".into(),
                    ));
                }
                if let Some((subnet, row)) = rows.first() {
                    tx.subnet = Some((*subnet).clone());
                    tx.row = Some((*row).clone());
                }
                (true, Some(name), Some(mask))
            }
            AddressRequest::RemoveManual { name, ip }
            | AddressRequest::RemovePrimary { name, ip } => {
                ip.parse::<Ipv4Addr>()
                    .map_err(|_| AppError::Network("Invalid IPv4 address".into()))?;
                tx.address = ip;
                let rows: Vec<_> = settings
                    .adopted_meta
                    .iter()
                    .filter(|(_, r)| r.address.as_ref() == Some(&tx.address))
                    .collect();
                if rows.len() > 1 {
                    return Err(AppError::Network(
                        "Saved address ownership is ambiguous; no OS change made".into(),
                    ));
                }
                if let Some((subnet, row)) = rows.first() {
                    tx.subnet = Some((*subnet).clone());
                    tx.row = Some((*row).clone());
                }
                (false, Some(name), None)
            }
            AddressRequest::RemoveSaved { subnet, hint } => {
                tx.row = Some(
                    settings
                        .adopted_meta
                        .get(&subnet)
                        .cloned()
                        .ok_or_else(|| AppError::Network("Unknown saved binding".into()))?,
                );
                tx.address = tx
                    .row
                    .as_ref()
                    .and_then(|r| r.address.clone())
                    .ok_or_else(|| AppError::Network("Saved address is unknown".into()))?;
                tx.subnet = Some(subnet);
                (false, hint, None)
            }
        };
        if !add {
            if let (Some(subnet), Some(row)) = (tx.subnet.as_deref(), tx.row.clone()) {
                tx.address
                    .parse::<Ipv4Addr>()
                    .map_err(|_| AppError::Network("Saved address is invalid".into()))?;
                if row.adapter_mac.as_deref().and_then(adapter_mac).is_none()
                    || row.prefix.is_none_or(|p| p > 32)
                {
                    return Err(AppError::Network(
                        "Saved address ownership or prefix is unknown; no OS change made".into(),
                    ));
                }
                if tx.prefix.is_some_and(|prefix| row.prefix != Some(prefix)) {
                    return Err(AppError::Network(
                        "Previous primary prefix changed; no removal made".into(),
                    ));
                }
                tx.prefix = row.prefix;
                let row = pending_binding_removal(row);
                let saved = self.address_io.persist_intent(config, subnet, row.clone());
                tx.trace.phase("intent_save");
                saved?;
                tx.intent_saved = true;
                tx.row = Some(row.clone());
                self.adopted_ips.lock().await.remove(subnet);
                self.adopted_meta
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(subnet.into(), row);
            }
        }
        log::info!(
            "event=address_target operation={} address={} prefix={}",
            tx.trace.id,
            log_value(&tx.address),
            tx.prefix
                .map_or_else(|| "unknown".into(), |p| p.to_string())
        );
        let before = self
            .operation_snapshot_traced(config, Some(&tx.trace))
            .await;
        tx.trace.phase("preflight");
        let before = before?;
        tx.trace.identity(&before, tx.prefix);
        self.validate_operation_context(config, tx, fence)?;
        if (add && !before.selected.is_up)
            || alias
                .as_ref()
                .is_some_and(|name| *name != before.selected.alias)
        {
            return Err(AppError::Network(
                "Selected Ethernet adapter unavailable or changed".into(),
            ));
        }
        if add && (before.selected.dhcp || tx.mode == NetworkMode::Dhcp) {
            return Err(AppError::Network(
                "Adapter is DHCP; switch to a static mode before adding an address".into(),
            ));
        }
        let existing = before.selected.ips.iter().find(|a| a.address == tx.address);
        if tx.prefix.is_none() {
            tx.prefix = existing.map(|i| i.prefix);
        }
        if existing.is_some_and(|i| tx.prefix != Some(i.prefix)) {
            return Err(AppError::Network(
                "Address exists with a different prefix; no OS change made".into(),
            ));
        }
        if add
            && before.all.iter().any(|a| {
                a.identity() != before.selected.identity()
                    && a.ips.iter().any(|i| i.address == tx.address)
            })
        {
            return Err(AppError::Network(
                "Address is already assigned to another local adapter".into(),
            ));
        }
        if !add
            && settings.pending_addresses.iter().any(|p| {
                p.address == tx.address
                    && Some(p.prefix) == tx.prefix
                    && adapter_mac(&p.adapter_mac) == adapter_mac(&before.selected.mac)
            })
        {
            tx.trace.phase("ownership_pending");
            tx.outcome = AddressOutcome::Pending;
            return Err(AppError::Network("Waiting for current network operation; temporary ownership cleanup remains pending".into()));
        }
        if !add && tx.subnet.is_some() {
            return self.remove_saved_operation(config, before, fence, tx).await;
        }
        // Track unmanaged removal durably until Windows confirms absence.
        // Fresh discovery may adopt again after completion. Never overwrite
        // another address's saved row to record this removal.
        if !add {
            if let Some(prefix) = tx.prefix {
                let subnet = ipnetwork::Ipv4Network::new(tx.address.parse().unwrap(), prefix)
                    .map_err(|e| AppError::Network(e.to_string()))?
                    .network();
                let key = format!("{subnet}/{prefix}");
                if !settings.adopted_meta.contains_key(&key) {
                    let row = pending_binding_removal(AdoptedMeta {
                        adapter_mac: tx.mac.clone(),
                        address: Some(tx.address.clone()),
                        prefix: Some(prefix),
                        applied: existing.is_some(),
                        ..Default::default()
                    });
                    self.address_io.persist_intent(config, &key, row.clone())?;
                    tx.intent_saved = true;
                    tx.subnet = Some(key.clone());
                    tx.row = Some(row.clone());
                    self.adopted_meta
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(key, row);
                    return self.remove_saved_operation(config, before, fence, tx).await;
                }
            }
        }
        tx.trace.phase("os_command_start");
        let command = if add && existing.is_none() {
            self.address_io
                .add(&before.selected, &tx.address, mask.as_deref().unwrap())
                .await
        } else if !add && existing.is_some() {
            self.address_io.remove(&before.selected, &tx.address).await
        } else {
            Ok(())
        };
        tx.trace.phase("os_command");
        let observed = self
            .observe_address_state(config, &before, fence, tx, add)
            .await;
        tx.trace.phase("observation");
        match observed {
            Ok(after) => {
                let established = requested_state(&after, &tx.address, tx.prefix, add);
                tx.observed = Some(after);
                if add && established {
                    // Explicit claim remains a manual/external address, even when
                    // a command error is retained alongside its observed effect.
                    if let Err(error) = self
                        .claim_binding_locked(config, &tx.address, &before.selected.alias)
                        .await
                    {
                        tx.reason = Some(match command {
                            Err(command_error) => format!("{command_error}; {error}"),
                            Ok(()) => error.to_string(),
                        });
                        if let Some(row) = &mut tx.row {
                            row.applied = true;
                            row.last_error = tx.reason.clone();
                        }
                        tx.trace.phase("status_save");
                        tx.outcome = AddressOutcome::Failed;
                        return Ok(());
                    }
                    tx.row = None;
                    tx.trace.phase("status_save");
                }
                if let Err(error) = command {
                    tx.reason = Some(error.to_string());
                    tx.outcome = AddressOutcome::Failed;
                } else if established {
                    tx.outcome = AddressOutcome::Success;
                } else {
                    tx.outcome = AddressOutcome::Pending;
                    tx.reason =
                        Some("Windows has not confirmed the requested address state".into());
                }
            }
            Err(error) => {
                tx.observation_error = Some(error.to_string());
                tx.outcome = AddressOutcome::Pending;
                tx.reason = Some(
                    command
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| error.to_string()),
                );
            }
        }
        Ok(())
    }

    /// Resolve the exact prior primary; multiple legacy addresses require an
    /// explicit choice. This is checked before the mode writer changes Windows.
    pub(super) fn primary_to_replace(
        &self,
        config: &AppConfig,
        before: &OperationSnapshot,
        request: &ModeTransition,
    ) -> Result<Option<interface::IpInfo>, AppError> {
        let settings = config.get();
        let saved = settings
            .primary_addresses
            .get(&before.selected.identity().mac);
        if request.ip.as_ref().is_some_and(|ip| {
            before.all.iter().any(|a| {
                a.identity() != before.selected.identity() && a.ips.iter().any(|i| &i.address == ip)
            })
        }) {
            return Err(AppError::Network(
                "Primary address is assigned to another local adapter".into(),
            ));
        }
        let choice = request
            .previous_address
            .as_ref()
            .or(saved.filter(|s| !s.is_empty()));
        if let Some(cidr) = choice {
            let (ip, prefix) = crate::validation::parse_cidr(cidr)?;
            if let Some(found) = before
                .selected
                .ips
                .iter()
                .find(|a| a.address == ip.to_string())
            {
                if found.prefix != prefix {
                    return Err(AppError::Network(
                        "Primary prefix changed; reopen Configure".into(),
                    ));
                }
                let owners: Vec<_> = settings
                    .adopted_meta
                    .values()
                    .filter(|r| r.address.as_deref() == Some(found.address.as_str()))
                    .collect();
                if owners.len() > 1
                    || owners.iter().any(|r| {
                        r.prefix != Some(prefix)
                            || r.adapter_mac.as_deref().and_then(adapter_mac)
                                != Some(before.selected.identity().mac.clone())
                    })
                {
                    return Err(AppError::Network(
                        "Previous primary ownership is unknown or changed".into(),
                    ));
                }
                return Ok(Some(found.clone()));
            }
            // A successful native snapshot proves this exact old address is
            // already absent. Create the new primary without deleting another.
            return Ok(None);
        }
        if saved.is_some_and(|s| s.is_empty()) {
            return Ok(None);
        }
        let usable: Vec<_> = before
            .selected
            .ips
            .iter()
            .filter(|a| !a.address.starts_with("169.254."))
            .collect();
        let manual: Vec<_> = usable
            .iter()
            .filter(|a| {
                !settings.adopted_meta.values().any(|r| {
                    r.address.as_ref() == Some(&a.address) && r.desired == BindingDesired::Present
                })
            })
            .collect();
        if manual.len() == 1 {
            return Ok(Some((**manual[0]).clone()));
        }
        if usable.len() == 1 {
            return Ok(Some(usable[0].clone()));
        }
        if usable.is_empty() {
            return Ok(None);
        }
        Err(AppError::Network(
            "Select the address to replace in Configure".into(),
        ))
    }

    /// The mode writer first establishes the new address while preserving old
    /// addresses. Only an observed new primary permits retiring the old tuple.
    pub(super) async fn finish_primary_change(
        &self,
        config: &AppConfig,
        before: &OperationSnapshot,
        request: &ModeTransition,
        previous: Option<interface::IpInfo>,
    ) -> Result<(), AppError> {
        let after = self.operation_snapshot(config).await?;
        let ip = request
            .ip
            .as_deref()
            .ok_or_else(|| AppError::Network("Primary address required".into()))?;
        let prefix = ip_config::mask_to_prefix(request.subnet_mask.as_deref().unwrap_or(""))?;
        if after.selected.identity() != before.selected.identity()
            || after.selected.dhcp
            || !after
                .selected
                .ips
                .iter()
                .any(|a| a.address == ip && a.prefix == prefix)
        {
            return Err(AppError::Network(
                "Windows has not confirmed the new primary address".into(),
            ));
        }
        let mac = after.selected.identity().mac;
        // Durable manual ownership of the observed new address must succeed
        // before the old primary can be removed, including pending ownership.
        self.claim_binding_locked(config, ip, &after.selected.alias)
            .await?;
        self.address_io
            .persist_primary(config, &mac, &format!("{ip}/{prefix}"))?;
        let Some(previous) = previous.filter(|a| a.address != ip) else {
            return Ok(());
        };
        // Reuse the exact same intent-save, native verification and targeted
        // removal path as the modal. The caller already holds both locks.
        let fence = self.presence.snapshot().fence;
        let mut tx = Transaction {
            trace: AddressTrace::new("replace_primary", &previous.address),
            mac: Some(mac),
            mode: config.get_network_mode(),
            address: previous.address.clone(),
            prefix: Some(previous.prefix),
            subnet: None,
            row: None,
            observed: None,
            observation_error: None,
            intent_saved: false,
            outcome: AddressOutcome::Failed,
            reason: None,
        };
        let result = self
            .run_address_operation(
                config,
                AddressRequest::RemoveManual {
                    name: after.selected.alias,
                    ip: previous.address,
                },
                &fence,
                &mut tx,
            )
            .await;
        if let Err(error) = result {
            if tx.intent_saved {
                if let (Some(subnet), Some(mut row)) = (tx.subnet.as_deref(), tx.row.clone()) {
                    row.last_error = Some(error.to_string());
                    self.publish_binding(config, subnet, row).await;
                }
            }
            return Err(error);
        }
        if tx.outcome != AddressOutcome::Success {
            return Err(AppError::Network(
                tx.reason
                    .unwrap_or_else(|| "Primary replacement remains pending".into()),
            ));
        }
        Ok(())
    }

    fn validate_operation_context(
        &self,
        config: &AppConfig,
        tx: &Transaction,
        fence: &SweepFence,
    ) -> Result<(), AppError> {
        let now = config.get();
        if now.selected_adapter_mac.as_deref().and_then(adapter_mac)
            != tx.mac.as_deref().and_then(adapter_mac)
            || now.network_mode != tx.mode
            || fence.is_stale()
        {
            Err(AppError::Network(
                "Network selection or mode changed; retry the operation".into(),
            ))
        } else {
            Ok(())
        }
    }

    async fn observe_address_state(
        &self,
        config: &AppConfig,
        before: &OperationSnapshot,
        fence: &SweepFence,
        tx: &Transaction,
        add: bool,
    ) -> Result<OperationSnapshot, AppError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let after = tokio::time::timeout_at(
                deadline,
                self.observe_operation_traced(before, Some(&tx.trace)),
            )
            .await
            .map_err(|_| {
                AppError::Network("Address verification timed out; current state is unknown".into())
            })??;
            self.validate_operation_context(config, tx, fence)?;
            if requested_state(&after, &tx.address, tx.prefix, add) {
                return Ok(after);
            }
            if tokio::time::Instant::now() + Duration::from_millis(50) >= deadline {
                return Ok(after);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn remove_saved_operation(
        &self,
        config: &AppConfig,
        before: OperationSnapshot,
        fence: &SweepFence,
        tx: &mut Transaction,
    ) -> Result<(), AppError> {
        let subnet = tx.subnet.clone().unwrap();
        let row = tx.row.clone().unwrap();
        // With no write needed, still take a fresh final observation. A genuine
        // intervening change is reconciled once, rather than blindly retried.
        let before = if requested_state(&before, &tx.address, tx.prefix, false) {
            self.observe_address_state(config, &before, fence, tx, false)
                .await?
        } else {
            before
        };
        let observed = StdMutex::new(None);
        let snapshot = Ok(before.clone());
        tx.trace.phase("os_command_start");
        let row = self
            .reconcile_binding_row(
                config,
                &subnet,
                row,
                BindingContext {
                    snapshot: &snapshot,
                    mode: tx.mode,
                    trace: Some(&tx.trace),
                },
                || async {
                    tx.trace.phase("os_command");
                    let result = self
                        .observe_address_state(config, &before, fence, tx, false)
                        .await;
                    let ips = result
                        .as_ref()
                        .map_err(|e| AppError::Network(e.to_string()))
                        .and_then(|s| {
                            if s.selected
                                .ips
                                .iter()
                                .any(|i| i.address == tx.address && Some(i.prefix) != tx.prefix)
                            {
                                Err(AppError::Network(
                                    "Address now has a different prefix; removal is unconfirmed"
                                        .into(),
                                ))
                            } else {
                                Ok(s.selected.ips.clone())
                            }
                        });
                    *observed.lock().unwrap() = Some(result);
                    ips
                },
            )
            .await;
        let post = observed.into_inner().unwrap().unwrap_or(Ok(before));
        tx.row = Some(row.clone());
        match post {
            Ok(after) => {
                tx.observed = Some(after);
            }
            Err(error) => {
                tx.observation_error = Some(error.to_string());
            }
        }
        tx.reason = row.last_error;
        tx.outcome = if tx.reason.is_none() && !row.applied {
            AddressOutcome::Success
        } else if tx.observation_error.is_some() || row.applied {
            AddressOutcome::Pending
        } else {
            AddressOutcome::Failed
        };
        Ok(())
    }
}

fn requested_state(snapshot: &OperationSnapshot, ip: &str, prefix: Option<u8>, add: bool) -> bool {
    if add {
        snapshot
            .selected
            .ips
            .iter()
            .any(|a| a.address == ip && Some(a.prefix) == prefix)
    } else {
        snapshot.selected.ips.iter().all(|a| a.address != ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppSettings, BindingDesired, PendingAddress};
    use interface::{
        address_test_io::{Effect, FakeAddressIo},
        AddressFuture, AddressIo, NativeAdapter,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Same manager seam; production atomic settings closures run against memory,
    // never a user's config file. Native/writer/callback behavior is shared with SP1.
    struct TestIo {
        os: Arc<FakeAddressIo>,
        events: StdMutex<Vec<String>>,
        qualified: StdMutex<Vec<(interface::NativeIdentity, InterfaceInfo)>>,
        saves: AtomicUsize,
        fail_save: AtomicUsize,
    }
    impl TestIo {
        fn persist(&self, kind: &str, subnet: &str) -> Result<(), AppError> {
            self.events.lock().unwrap().push(format!("{kind}:{subnet}"));
            let n = self.saves.fetch_add(1, Ordering::Relaxed) + 1;
            if self.fail_save.load(Ordering::Relaxed) == n {
                Err(AppError::Config("injected atomic save failure".into()))
            } else {
                Ok(())
            }
        }
    }
    impl AddressIo for TestIo {
        fn native(&self) -> AddressFuture<'_, Vec<NativeAdapter>> {
            self.events.lock().unwrap().push("read".into());
            self.os.native()
        }
        fn add<'a>(
            &'a self,
            n: &'a NativeAdapter,
            ip: &'a str,
            mask: &'a str,
        ) -> AddressFuture<'a, ()> {
            self.events.lock().unwrap().push(format!("add:{ip}"));
            self.os.add(n, ip, mask)
        }
        fn remove<'a>(&'a self, n: &'a NativeAdapter, ip: &'a str) -> AddressFuture<'a, ()> {
            self.events.lock().unwrap().push(format!("remove:{ip}"));
            self.os.remove(n, ip)
        }
        fn descriptor(&self, n: &NativeAdapter) -> Option<InterfaceInfo> {
            self.os.descriptor(n).or_else(|| {
                self.qualified
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(identity, _)| *identity == n.identity())
                    .map(|(_, metadata)| n.overlay(metadata))
            })
        }
        fn qualify(&self) -> AddressFuture<'_, ()> {
            self.os.qualify()
        }
        fn persist_binding(
            &self,
            c: &AppConfig,
            subnet: &str,
            row: AdoptedMeta,
        ) -> Result<(), AppError> {
            c.set_binding_for_operation_with(subnet, row, false, |_| self.persist("status", subnet))
        }
        fn persist_intent(
            &self,
            c: &AppConfig,
            subnet: &str,
            row: AdoptedMeta,
        ) -> Result<(), AppError> {
            c.set_binding_for_operation_with(subnet, row, true, |_| self.persist("intent", subnet))
        }
        fn claim(&self, c: &AppConfig, ip: &str) -> Result<(), AppError> {
            c.claim_binding_with(ip, |_| self.persist("claim", ip))
        }
        fn forget_completed_removal(
            &self,
            c: &AppConfig,
            subnet: &str,
            expected: &AdoptedMeta,
        ) -> Result<(), AppError> {
            c.forget_completed_removal_with(subnet, expected, |_| self.persist("retire", subnet))
        }
        fn persist_primary(&self, c: &AppConfig, mac: &str, cidr: &str) -> Result<(), AppError> {
            c.set_primary_address_with(mac, cidr, |_| self.persist("primary", cidr))
        }
    }
    const TARGET: &str = "192.0.2.0/24";
    const IP: &str = "192.0.2.20";
    fn fixture(count: usize) -> (Arc<NetworkManager>, Arc<AppConfig>, Arc<TestIo>) {
        let os = FakeAddressIo::new(&["192.0.2.10", IP]);
        let io = Arc::new(TestIo {
            os,
            events: StdMutex::new(vec![]),
            qualified: StdMutex::new(vec![]),
            saves: AtomicUsize::new(0),
            fail_save: AtomicUsize::new(0),
        });
        let manager = Arc::new(NetworkManager::with_address_io(io.clone()));
        let mut settings = AppSettings {
            selected_adapter_mac: Some("40:cd:3a:00:00:01".into()),
            ..Default::default()
        };
        for i in 0..count {
            let subnet = if i == 0 {
                TARGET.into()
            } else {
                format!("198.51.{i}.0/24")
            };
            let ip = if i == 0 {
                IP.into()
            } else {
                format!("198.51.{i}.20")
            };
            settings.adopted_subnets.insert(subnet.clone(), ip.clone());
            settings.adopted_meta.insert(
                subnet,
                AdoptedMeta {
                    adapter_mac: settings.selected_adapter_mac.clone(),
                    prefix: Some(24),
                    address: Some(ip),
                    applied: true,
                    ..Default::default()
                },
            );
        }
        (
            manager,
            Arc::new(AppConfig::temporary_test_config(settings)),
            io,
        )
    }
    fn removal() -> AddressRequest {
        AddressRequest::RemoveSaved {
            subnet: TARGET.into(),
            hint: Some("Ethernet".into()),
        }
    }

    fn adoption_test_fence() -> SweepFence {
        SweepFence::new(
            1,
            Arc::new(AtomicU64::new(1)),
            Arc::new(AtomicBool::new(true)),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn completed_removal_allows_fresh_adoption_in_session_and_after_restart() {
        for managed in [false, true] {
            for restart in [false, true] {
                let (m, c, io) = fixture(usize::from(managed));
                {
                    let mut table = io.os.table.lock().unwrap();
                    let primary = &mut table[0].ips[0];
                    primary.address = "192.168.2.100".into();
                    primary.subnet = "192.168.2.0/24".into();
                }
                c.settings
                    .lock()
                    .unwrap()
                    .primary_addresses
                    .insert("40:cd:3a:00:00:01".into(), "192.168.2.100/24".into());
                let request = if managed {
                    removal()
                } else {
                    AddressRequest::RemoveManual {
                        name: "Ethernet".into(),
                        ip: IP.into(),
                    }
                };
                let result = m.address_operation(&c, request).await;
                assert_eq!(result.outcome, AddressOutcome::Success);
                assert!(c.get().adopted_meta[TARGET].removal_complete());
                let before = c.get();
                let c = if restart {
                    Arc::new(AppConfig::temporary_test_config(
                        crate::config::test_support::parse_for_test(
                            &crate::config::test_support::serialize_for_test(&before),
                        )
                        .unwrap(),
                    ))
                } else {
                    c
                };
                let manager = NetworkManager::with_address_io(io.clone());
                *manager.adopted_meta.lock().unwrap() = c.get().adopted_meta.clone();
                let session = adoption_test_fence();
                let address = manager.address_fence();
                manager
                    .prepare_subnet_adoption(&c, TARGET, "40:cd:3a:00:00:01", 7, &session, &address)
                    .await
                    .unwrap();
                assert!(!c.get().adopted_meta.contains_key(TARGET));
                assert!(!manager.adopted_meta.lock().unwrap().contains_key(TARGET));
                assert!(c.get().adopted_subnets.is_empty());
                assert_eq!(c.get().primary_addresses, before.primary_addresses);
                assert_eq!(*io.os.writes.lock().unwrap(), [(false, IP.into())]);
                assert!(io.os.table.lock().unwrap()[0]
                    .ips
                    .iter()
                    .any(|i| i.address == "192.168.2.100"));
                assert!(io
                    .events
                    .lock()
                    .unwrap()
                    .contains(&format!("retire:{TARGET}")));
                // The normal commit path can now accept a freshly verified
                // adoption; a late status write could not clear the tombstone.
                c.set_binding_for_operation_with(
                    TARGET,
                    AdoptedMeta {
                        adapter_mac: Some("40:cd:3a:00:00:01".into()),
                        address: Some(IP.into()),
                        prefix: Some(24),
                        applied: true,
                        ..Default::default()
                    },
                    false,
                    |_| Ok(()),
                )
                .unwrap();
                assert_eq!(c.get().adopted_subnets[TARGET], IP);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_adoption_never_bypasses_pending_removal_or_unknown_native_state() {
        for case in 0..15 {
            let (m, c, io) = fixture(1);
            let mut row = c.get().adopted_meta[TARGET].clone();
            row.desired = BindingDesired::Removed;
            row.applied = false;
            io.os.table.lock().unwrap()[0]
                .ips
                .retain(|i| i.address != IP);
            let session = adoption_test_fence();
            let address = adoption_test_fence();
            match case {
                0 => row.desired = BindingDesired::Present,
                1 => row.applied = true,
                2 => row.last_error = Some("Removal awaiting Windows confirmation".into()),
                3 => io.os.fail_read.store(true, Ordering::Relaxed),
                4 => io.os.table.lock().unwrap()[0].dhcp = true,
                5 => io.os.table.lock().unwrap()[0].is_up = false,
                6 => io.os.table.lock().unwrap()[0].index = 8,
                7 => row.adapter_mac = Some("aa:bb:cc:dd:ee:ff".into()),
                8 => session.active.store(false, Ordering::Relaxed),
                9 => address.current.store(2, Ordering::Relaxed),
                10 => io.os.table.lock().unwrap()[0].ips.push(interface::IpInfo {
                    address: IP.into(),
                    prefix: 24,
                    subnet: TARGET.into(),
                }),
                11 => io.os.table.lock().unwrap()[0].ips.push(interface::IpInfo {
                    address: IP.into(),
                    prefix: 25,
                    subnet: "192.0.2.0/25".into(),
                }),
                12 => row.prefix = None,
                13 => c.settings.lock().unwrap().network_mode = NetworkMode::Dhcp,
                _ => c.settings.lock().unwrap().network_mode = NetworkMode::StaticManual,
            }
            {
                let mut settings = c.settings.lock().unwrap();
                settings.adopted_subnets.clear();
                settings.adopted_meta.insert(TARGET.into(), row.clone());
            }
            assert!(
                m.prepare_subnet_adoption(&c, TARGET, "40:cd:3a:00:00:01", 7, &session, &address,)
                    .await
                    .is_err(),
                "case {case}"
            );
            assert_eq!(c.get().adopted_meta[TARGET], row, "case {case}");
            assert!(io.os.writes.lock().unwrap().is_empty());
            assert!(!io
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|e| e.starts_with("retire:")));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn completed_removal_save_failure_keeps_intent_and_prevents_adoption() {
        let (m, c, io) = fixture(1);
        assert_eq!(
            m.address_operation(&c, removal()).await.outcome,
            AddressOutcome::Success
        );
        let before = c.get().adopted_meta[TARGET].clone();
        let saves = io.saves.load(Ordering::Relaxed);
        io.fail_save.store(saves + 1, Ordering::Relaxed);
        let fence = adoption_test_fence();
        assert!(m
            .prepare_subnet_adoption(&c, TARGET, "40:cd:3a:00:00:01", 7, &fence, &fence,)
            .await
            .is_err());
        assert_eq!(c.get().adopted_meta[TARGET], before);
        assert_eq!(m.adopted_meta.lock().unwrap()[TARGET], before);
        assert_eq!(*io.os.writes.lock().unwrap(), [(false, IP.into())]);
        io.fail_save.store(0, Ordering::Relaxed);
        m.prepare_subnet_adoption(&c, TARGET, "40:cd:3a:00:00:01", 7, &fence, &fence)
            .await
            .unwrap();
        assert!(!c.get().adopted_meta.contains_key(TARGET));
    }

    fn primary_request(previous: Option<&str>) -> ModeTransition {
        ModeTransition {
            name: "Ethernet".into(),
            mode: NetworkMode::StaticAuto,
            ip: Some("198.51.100.10".into()),
            subnet_mask: Some("255.255.255.0".into()),
            gateway: None,
            previous_address: previous.map(str::to_owned),
            confirmed: false,
        }
    }
    fn establish_new_primary(io: &TestIo) {
        io.os.table.lock().unwrap()[0].ips.push(interface::IpInfo {
            address: "198.51.100.10".into(),
            prefix: 24,
            subnet: "198.51.100.0/24".into(),
        });
    }

    #[tokio::test(start_paused = true)]
    async fn primary_replacement_removes_only_the_explicit_old_tuple_in_both_orders() {
        for old in ["192.0.2.10", IP] {
            for reverse in [false, true] {
                let (m, c, io) = fixture(1);
                if reverse {
                    io.os.table.lock().unwrap()[0].ips.reverse();
                }
                let before = m.operation_snapshot(&c).await.unwrap();
                let request = primary_request(Some(&format!("{old}/24")));
                let previous = m.primary_to_replace(&c, &before, &request).unwrap();
                establish_new_primary(&io);
                m.finish_primary_change(&c, &before, &request, previous)
                    .await
                    .unwrap();
                assert_eq!(*io.os.writes.lock().unwrap(), vec![(false, old.into())]);
                assert!(io.os.table.lock().unwrap()[0]
                    .ips
                    .iter()
                    .any(|i| i.address == "198.51.100.10"));
                assert_eq!(
                    c.get().primary_addresses["40:cd:3a:00:00:01"],
                    "198.51.100.10/24"
                );
                if old == IP {
                    assert_eq!(
                        c.get().adopted_meta[TARGET].desired,
                        BindingDesired::Removed
                    );
                } else {
                    assert_eq!(
                        c.get().adopted_meta[TARGET].desired,
                        BindingDesired::Present
                    );
                }
                let snapshot = m.operation_snapshot(&c).await.unwrap();
                let mut next = primary_request(None);
                next.ip = Some("203.0.113.10".into());
                assert_eq!(
                    m.primary_to_replace(&c, &snapshot, &next)
                        .unwrap()
                        .unwrap()
                        .address,
                    "198.51.100.10"
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_or_unestablished_primary_never_removes_the_old_address() {
        for fail_native in [false, true] {
            let (m, c, io) = fixture(1);
            let before = m.operation_snapshot(&c).await.unwrap();
            let request = primary_request(Some("192.0.2.10/24"));
            let previous = m.primary_to_replace(&c, &before, &request).unwrap();
            io.os.fail_read.store(fail_native, Ordering::Relaxed);
            assert!(m
                .finish_primary_change(&c, &before, &request, previous)
                .await
                .is_err());
            assert!(io.os.writes.lock().unwrap().is_empty());
            assert!(c.get().primary_addresses.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn primary_replacement_save_errors_and_failed_deletes_are_not_success() {
        for case in 0..7 {
            let (m, c, io) = fixture(1);
            let before = m.operation_snapshot(&c).await.unwrap();
            let request = primary_request(Some(&format!("{IP}/24")));
            let previous = m.primary_to_replace(&c, &before, &request).unwrap();
            establish_new_primary(&io);
            match case {
                0..=3 => io.fail_save.store(case + 1, Ordering::Relaxed),
                4 => *io.os.effect.lock().unwrap() = Effect::Unchanged,
                5 => *io.os.effect.lock().unwrap() = Effect::ErrorAfter,
                _ => *io.os.effect.lock().unwrap() = Effect::TimeoutAfter,
            }
            assert!(
                m.finish_primary_change(&c, &before, &request, previous)
                    .await
                    .is_err(),
                "case {case}"
            );
            assert_eq!(
                io.os.writes.lock().unwrap().len(),
                usize::from(case >= 3),
                "case {case}"
            );
            if case >= 3 {
                assert_eq!(
                    c.get().adopted_meta[TARGET].desired,
                    BindingDesired::Removed
                );
            }
            assert!(io.os.table.lock().unwrap()[0]
                .ips
                .iter()
                .any(|i| i.address == "198.51.100.10"));
        }
    }

    #[tokio::test]
    async fn legacy_ambiguous_primary_requires_a_choice_and_prefix_change_is_refused() {
        let (m, c, io) = fixture(0);
        let before = m.operation_snapshot(&c).await.unwrap();
        assert!(m
            .primary_to_replace(&c, &before, &primary_request(None))
            .is_err());
        assert!(m
            .primary_to_replace(&c, &before, &primary_request(Some("192.0.2.10/25")))
            .is_err());
        assert!(io.os.writes.lock().unwrap().is_empty());
        let mut conflicting = before.clone();
        let mut other = before.selected.clone();
        other.mac = "40:cd:3a:00:00:02".into();
        other.guid = "other".into();
        other.index = 8;
        other.ips.push(interface::IpInfo {
            address: "198.51.100.10".into(),
            prefix: 24,
            subnet: "198.51.100.0/24".into(),
        });
        conflicting.all.push(other);
        assert!(m
            .primary_to_replace(&c, &conflicting, &primary_request(Some("192.0.2.10/24")))
            .is_err());
        c.settings.lock().unwrap().adopted_meta.insert(
            TARGET.into(),
            AdoptedMeta {
                address: Some("192.0.2.10".into()),
                prefix: Some(24),
                adapter_mac: None,
                ..Default::default()
            },
        );
        assert!(m
            .primary_to_replace(&c, &before, &primary_request(Some("192.0.2.10/24")))
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_removal_works_on_present_disconnected_adapter_and_keeps_intent() {
        for managed in [false, true] {
            let (m, c, io) = fixture(usize::from(managed));
            io.os.table.lock().unwrap()[0].is_up = false;
            if managed {
                c.settings
                    .lock()
                    .unwrap()
                    .primary_addresses
                    .insert("40:cd:3a:00:00:01".into(), format!("{IP}/24"));
            }
            let reply = m
                .address_operation(
                    &c,
                    if managed {
                        AddressRequest::RemoveManual {
                            name: "Ethernet".into(),
                            ip: IP.into(),
                        }
                    } else {
                        AddressRequest::RemovePrimary {
                            name: "Ethernet".into(),
                            ip: IP.into(),
                        }
                    },
                )
                .await;
            assert_eq!(reply.outcome, AddressOutcome::Success);
            assert_eq!(reply.view.primary_address.as_deref(), Some(""));
            assert_eq!(*io.os.writes.lock().unwrap(), vec![(false, IP.into())]);
            let row = &c.get().adopted_meta[TARGET];
            assert_eq!(row.desired, BindingDesired::Removed);
            assert!(!row.applied);
            let events = io.events.lock().unwrap();
            assert!(
                events
                    .iter()
                    .position(|x| x == &format!("intent:{TARGET}"))
                    .unwrap()
                    < events
                        .iter()
                        .position(|x| x == &format!("remove:{IP}"))
                        .unwrap()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_primary_clear_reports_absence_without_false_success_and_can_retry() {
        let (m, c, io) = fixture(0);
        io.fail_save.store(3, Ordering::Relaxed);
        let reply = m
            .address_operation(
                &c,
                AddressRequest::RemovePrimary {
                    name: "Ethernet".into(),
                    ip: IP.into(),
                },
            )
            .await;
        assert_eq!(reply.outcome, AddressOutcome::Failed);
        assert!(!reply
            .view
            .selection
            .adapter
            .unwrap()
            .ips
            .iter()
            .any(|i| i.address == IP));
        assert!(c.get().primary_addresses.is_empty());
        let retry = m
            .address_operation(
                &c,
                AddressRequest::RemovePrimary {
                    name: "Ethernet".into(),
                    ip: IP.into(),
                },
            )
            .await;
        assert_eq!(retry.outcome, AddressOutcome::Success);
        assert_eq!(retry.view.primary_address.as_deref(), Some(""));
        assert_eq!(io.os.writes.lock().unwrap().len(), 1);
    }
    fn addition() -> AddressRequest {
        AddressRequest::Add {
            name: "Ethernet".into(),
            ip: IP.into(),
            mask: "255.255.255.0".into(),
        }
    }

    #[tokio::test]
    async fn sp08_targeted_remove_one_or_three_rows_preserves_unrelated_routes_and_save_order() {
        for count in [1, 3] {
            let (m, c, io) = fixture(count);
            *m.adopted_ips.lock().await = c
                .get()
                .adopted_subnets
                .iter()
                .map(|(k, v)| (k.clone(), v.parse().unwrap()))
                .collect();
            *m.adopted_meta.lock().unwrap() = c.get().adopted_meta.clone();
            let original = c.get();
            let reply = m.address_operation(&c, removal()).await;
            assert_eq!(reply.outcome, AddressOutcome::Success);
            assert!(!reply.view.binding.unwrap().applied);
            assert_eq!(io.os.reads.load(Ordering::Relaxed), 2);
            assert_eq!(io.os.providers.load(Ordering::Relaxed), 0);
            assert_eq!(*io.os.writes.lock().unwrap(), vec![(false, IP.into())]);
            assert_eq!(
                *io.events.lock().unwrap(),
                vec![
                    format!("intent:{TARGET}"),
                    "read".into(),
                    format!("remove:{IP}"),
                    "read".into(),
                    format!("status:{TARGET}")
                ]
            );
            let now = c.get();
            for (subnet, row) in original
                .adopted_meta
                .iter()
                .filter(|(s, _)| s.as_str() != TARGET)
            {
                assert_eq!(now.adopted_meta[subnet], *row);
                assert_eq!(m.adopted_meta.lock().unwrap()[subnet], *row);
                assert_eq!(
                    m.adopted_ips.lock().await[subnet].to_string(),
                    original.adopted_subnets[subnet]
                );
            }
            assert_eq!(m.adopted_ips.lock().await.len(), count - 1);
            assert!(reply
                .view
                .selection
                .adapter
                .unwrap()
                .ips
                .iter()
                .any(|i| i.address == "192.0.2.10"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn sp09_reply_preserves_command_evidence_and_unknown_observation_without_second_write() {
        for case in 0..7 {
            let (m, c, io) = fixture(1);
            match case {
                0 => *io.os.effect.lock().unwrap() = Effect::Unchanged,
                1 => *io.os.effect.lock().unwrap() = Effect::ErrorAfter,
                2 => *io.os.effect.lock().unwrap() = Effect::TimeoutAfter,
                3 => io.os.table.lock().unwrap().clear(),
                4 => io.os.fail_read_at.store(2, Ordering::Relaxed),
                5 => *io.os.post_delay.lock().unwrap() = Duration::from_secs(3),
                _ => io.os.fail_read.store(true, Ordering::Relaxed),
            }
            let reply = m.address_operation(&c, removal()).await;
            assert_ne!(reply.outcome, AddressOutcome::Success, "case {case}");
            let row = reply.view.binding.unwrap();
            assert_eq!(row.desired, BindingDesired::Removed);
            assert!(row.last_error.is_some());
            assert_eq!(
                io.os.writes.lock().unwrap().len(),
                usize::from(case != 3 && case != 6)
            );
            if case == 1 || case == 2 {
                assert_eq!(reply.outcome, AddressOutcome::Failed);
                assert!(!row.applied);
                assert!(reply.reason.unwrap().contains(if case == 1 {
                    "failure after effect"
                } else {
                    "timed out after effect"
                }));
                assert!(!reply
                    .view
                    .selection
                    .adapter
                    .unwrap()
                    .ips
                    .iter()
                    .any(|i| i.address == IP));
            } else {
                assert!(row.applied);
                if case != 0 {
                    assert!(reply.view.observation_error.is_some());
                }
            }
            tokio::time::advance(Duration::from_secs(20)).await;
            assert_eq!(
                io.os.writes.lock().unwrap().len(),
                usize::from(case != 3 && case != 6)
            );
        }
    }

    #[tokio::test]
    async fn sp09_add_retry_claims_observed_address_without_duplicating_os_write() {
        let (m, c, io) = fixture(1);
        io.os.table.lock().unwrap()[0]
            .ips
            .retain(|i| i.address != IP);
        *io.os.effect.lock().unwrap() = Effect::ErrorAfter;
        let first = m.address_operation(&c, addition()).await;
        assert_eq!(first.outcome, AddressOutcome::Failed);
        assert!(first.reason.unwrap().contains("failure after effect"));
        assert!(first
            .view
            .selection
            .adapter
            .unwrap()
            .ips
            .iter()
            .any(|i| i.address == IP));
        assert!(
            !c.get().adopted_meta.contains_key(TARGET),
            "explicit claim is manual, not managed"
        );
        let retry = m.address_operation(&c, addition()).await;
        assert_eq!(retry.outcome, AddressOutcome::Success);
        assert_eq!(io.os.writes.lock().unwrap().len(), 1);
        assert_eq!(io.os.providers.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn sp06_intent_failure_never_writes_and_status_failure_retains_durable_tombstone() {
        for fail in [1, 2] {
            let (m, c, io) = fixture(1);
            io.fail_save.store(fail, Ordering::Relaxed);
            let reply = m.address_operation(&c, removal()).await;
            assert_ne!(reply.outcome, AddressOutcome::Success);
            assert_eq!(io.os.writes.lock().unwrap().len(), usize::from(fail == 2));
            let durable = c.get().adopted_meta[TARGET].clone();
            if fail == 1 {
                assert_eq!(durable.desired, BindingDesired::Present);
            } else {
                assert_eq!(durable.desired, BindingDesired::Removed);
                assert!(
                    durable.applied,
                    "intent remains durable when the status save fails"
                );
                assert!(
                    !reply.view.binding.as_ref().unwrap().applied,
                    "observed absence is distinct from durable status"
                );
                assert!(reply.reason.unwrap().contains("status save failed"));
                let restarted = NetworkManager::with_address_io(io.clone());
                let again = restarted.address_operation(&c, removal()).await;
                assert_eq!(again.outcome, AddressOutcome::Success);
                assert_eq!(io.os.writes.lock().unwrap().len(), 1);
            }
        }
    }

    #[tokio::test]
    async fn sp06_failed_manual_claim_keeps_tombstone_and_command_error_with_observed_effect() {
        let (m, c, io) = fixture(1);
        {
            let mut s = c.settings.lock().unwrap();
            let r = s.adopted_meta.get_mut(TARGET).unwrap();
            r.desired = BindingDesired::Removed;
        }
        io.os.table.lock().unwrap()[0]
            .ips
            .retain(|i| i.address != IP);
        *io.os.effect.lock().unwrap() = Effect::ErrorAfter;
        io.fail_save.store(1, Ordering::Relaxed);
        let reply = m.address_operation(&c, addition()).await;
        assert_eq!(reply.outcome, AddressOutcome::Failed);
        assert!(reply
            .reason
            .as_ref()
            .unwrap()
            .contains("failure after effect"));
        assert!(reply.reason.unwrap().contains("atomic save failure"));
        assert!(reply
            .view
            .selection
            .adapter
            .unwrap()
            .ips
            .iter()
            .any(|i| i.address == IP));
        assert_eq!(
            c.get().adopted_meta[TARGET].desired,
            BindingDesired::Removed
        );
        assert!(reply.view.binding.unwrap().last_error.is_some());
    }

    #[tokio::test]
    async fn sp08_same_tuple_pending_owner_is_retained_and_explicit_claim_transfers_only_its_owner()
    {
        let (m, c, io) = fixture(1);
        c.settings.lock().unwrap().pending_addresses = vec![PendingAddress {
            adapter_mac: "40:cd:3a:00:00:01".into(),
            address: IP.into(),
            prefix: 24,
        }];
        m.pending_ips.lock().await.push(auto_adopt::PendingIp {
            iface: "Ethernet".into(),
            ip: IP.parse().unwrap(),
            adoption_id: 1,
        });
        m.pending_ips.lock().await.push(auto_adopt::PendingIp {
            iface: "Other".into(),
            ip: IP.parse().unwrap(),
            adoption_id: 2,
        });
        let pending = m.address_operation(&c, removal()).await;
        assert_eq!(pending.outcome, AddressOutcome::Pending);
        assert!(io.os.writes.lock().unwrap().is_empty());
        assert_eq!(c.get().pending_addresses.len(), 1);
        assert_eq!(m.pending_ips.lock().await.len(), 2);
        let claimed = m.address_operation(&c, addition()).await;
        assert_eq!(claimed.outcome, AddressOutcome::Success);
        assert!(c.get().pending_addresses.is_empty());
        assert!(!c.get().adopted_meta.contains_key(TARGET));
        assert_eq!(m.pending_ips.lock().await.len(), 1);
        assert_eq!(m.pending_ips.lock().await[0].iface, "Other");
    }

    #[tokio::test(start_paused = true)]
    async fn sp14_two_lock_waits_share_ten_seconds_release_pause_and_enqueue_nothing() {
        let (m, c, io) = fixture(1);
        let held_op = m.discovery_op.lock().await;
        let held_address = m.address_work.lock().await;
        let task = {
            let m = m.clone();
            let c = c.clone();
            tokio::spawn(async move { m.address_operation(&c, removal()).await })
        };
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(8)).await;
        c.settings.lock().unwrap().network_mode = NetworkMode::Dhcp;
        drop(held_op);
        tokio::task::yield_now().await;
        assert!(!m.address_active.load(Ordering::Acquire));
        tokio::time::advance(Duration::from_secs(2)).await;
        let reply = task.await.unwrap();
        assert_eq!(reply.outcome, AddressOutcome::Busy);
        assert_eq!(reply.view.mode, NetworkMode::Dhcp);
        assert!(m.address_active.load(Ordering::Acquire));
        drop(held_address);
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(io.events.lock().unwrap().is_empty());
        assert_eq!(io.saves.load(Ordering::Relaxed), 0);
        assert!(io.os.writes.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn sp14_native_deadline_fences_late_handler_and_admission_mode_changes() {
        for change_mode in [false, true] {
            let (m, c, io) = fixture(1);
            if !change_mode {
                *io.os.delay.lock().unwrap() = Duration::from_secs(3);
            }
            let held = m.discovery_op.lock().await;
            let task = {
                let m = m.clone();
                let c = c.clone();
                tokio::spawn(async move { m.address_operation(&c, addition()).await })
            };
            tokio::task::yield_now().await;
            if change_mode {
                c.settings.lock().unwrap().network_mode = NetworkMode::Dhcp;
            }
            drop(held);
            let reply = task.await.unwrap();
            assert_ne!(reply.outcome, AddressOutcome::Success);
            assert!(reply.view.observation_error.is_some());
            tokio::time::advance(Duration::from_secs(30)).await;
            assert!(io.os.writes.lock().unwrap().is_empty());
            assert_eq!(io.saves.load(Ordering::Relaxed), 0);
        }
    }
    #[tokio::test]
    async fn sp03_sp05_real_preflight_rejects_ambiguous_identity_prefix_and_saved_owner() {
        for case in 0..6 {
            let (m, c, io) = fixture(1);
            match case {
                0 => {
                    let mut t = io.os.table.lock().unwrap();
                    let mut other = t[0].clone();
                    other.index = 8;
                    other.guid = "other".into();
                    other.mac = "40:cd:3a:00:00:02".into();
                    t.push(other);
                }
                1 => {
                    io.os.table.lock().unwrap()[0]
                        .ips
                        .iter_mut()
                        .find(|i| i.address == IP)
                        .unwrap()
                        .prefix = 25
                }
                2 => {
                    c.settings
                        .lock()
                        .unwrap()
                        .adopted_meta
                        .get_mut(TARGET)
                        .unwrap()
                        .adapter_mac = None
                }
                3 => {
                    c.settings
                        .lock()
                        .unwrap()
                        .adopted_meta
                        .get_mut(TARGET)
                        .unwrap()
                        .adapter_mac = Some("40:cd:3a:00:00:02".into())
                }
                4 => {
                    let mut s = c.settings.lock().unwrap();
                    let row = s.adopted_meta[TARGET].clone();
                    s.adopted_meta.insert("192.0.0.0/16".into(), row);
                }
                _ => {
                    let mut t = io.os.table.lock().unwrap();
                    let mut other = t[0].clone();
                    other.alias = "Other".into();
                    other.guid = "other".into();
                    other.mac = "40:cd:3a:00:00:02".into();
                    t.push(other);
                }
            }
            let reply = m
                .address_operation(
                    &c,
                    AddressRequest::RemoveManual {
                        name: "Ethernet".into(),
                        ip: IP.into(),
                    },
                )
                .await;
            assert_ne!(reply.outcome, AddressOutcome::Success, "case {case}");
            assert!(io.os.writes.lock().unwrap().is_empty(), "case {case}");
        }
        // Enumeration order cannot redirect an operation or confer qualification.
        let (m, c, io) = fixture(1);
        {
            let mut t = io.os.table.lock().unwrap();
            // This fixture starts with two NICs, already qualified. Keep the
            // selected descriptor tied to its exact native identity; SP1's
            // single-NIC fake cache intentionally treats adding a NIC as new topology.
            io.qualified
                .lock()
                .unwrap()
                .push((t[0].identity(), io.os.descriptor(&t[0]).unwrap()));
            let mut other = t[0].clone();
            other.alias = "Other".into();
            other.guid = "other".into();
            other.index = 8;
            other.mac = "40:cd:3a:00:00:02".into();
            other.ips.clear();
            t.push(other);
            t.reverse();
        }
        let reply = m.address_operation(&c, removal()).await;
        assert_eq!(reply.outcome, AddressOutcome::Success);
        assert_eq!(reply.view.identity.unwrap().index, 7);
        assert_eq!(*io.os.writes.lock().unwrap(), vec![(false, IP.into())]);
    }

    #[tokio::test(start_paused = true)]
    async fn sp04_mode_change_during_post_write_observation_never_publishes_success() {
        let (m, c, io) = fixture(1);
        *io.os.post_delay.lock().unwrap() = Duration::from_millis(100);
        let task = {
            let m = m.clone();
            let c = c.clone();
            tokio::spawn(async move { m.address_operation(&c, removal()).await })
        };
        while io.os.writes.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        c.settings.lock().unwrap().network_mode = NetworkMode::Dhcp;
        tokio::time::advance(Duration::from_millis(100)).await;
        let reply = task.await.unwrap();
        assert_eq!(reply.outcome, AddressOutcome::Pending);
        assert_eq!(reply.view.mode, NetworkMode::Dhcp);
        assert!(reply.view.observation_error.is_some());
        assert_eq!(
            c.get().adopted_meta[TARGET].desired,
            BindingDesired::Removed
        );
        assert_eq!(io.os.writes.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn sp05_manual_claim_preserves_other_adapter_binding_and_live_route_for_same_ip() {
        let (m, c, io) = fixture(1);
        let foreign = "192.0.0.0/16";
        {
            let mut s = c.settings.lock().unwrap();
            let mut row = s.adopted_meta[TARGET].clone();
            row.adapter_mac = Some("40:cd:3a:00:00:02".into());
            s.adopted_meta.insert(foreign.into(), row);
            s.adopted_subnets.insert(foreign.into(), IP.into());
        }
        *m.adopted_meta.lock().unwrap() = c.get().adopted_meta.clone();
        m.adopted_ips
            .lock()
            .await
            .insert(foreign.into(), IP.parse().unwrap());
        let reply = m.address_operation(&c, addition()).await;
        assert_eq!(reply.outcome, AddressOutcome::Success);
        assert!(c.get().adopted_meta.contains_key(foreign));
        assert!(m.adopted_meta.lock().unwrap().contains_key(foreign));
        assert_eq!(m.adopted_ips.lock().await[foreign].to_string(), IP);
        assert!(!c.get().adopted_meta.contains_key(TARGET));
        assert!(io.os.writes.lock().unwrap().is_empty());
    }
}
