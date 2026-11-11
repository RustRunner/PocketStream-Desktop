//! One manager-owned retry task. Durable pending rows remain the only work list.
use super::{binding_store::BindingStore, local_executor::LocalExecutor, native_operations};
use crate::config::AppConfig;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, Notify};

#[derive(Default)]
struct State {
    closed: bool,
    requested: bool,
    task: Option<tokio::task::JoinHandle<()>>,
}

pub(super) struct TemporaryCleanup {
    state: Mutex<State>,
    wake: Notify,
    bindings: Weak<BindingStore>,
    discovery: Arc<AsyncMutex<()>>,
    config: Arc<AppConfig>,
    executor: LocalExecutor,
}

impl TemporaryCleanup {
    pub fn new(
        bindings: &Arc<BindingStore>,
        discovery: Arc<AsyncMutex<()>>,
        config: Arc<AppConfig>,
        executor: LocalExecutor,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            wake: Notify::new(),
            bindings: Arc::downgrade(bindings),
            discovery,
            config,
            executor,
        })
    }

    pub fn schedule(self: &Arc<Self>) {
        if self.config.get().pending_addresses.is_empty() {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        if !state.requested {
            state.requested = true;
            log::info!("event=temporary_cleanup outcome=scheduled");
        }
        if state.task.is_none() {
            let owner = self.clone();
            state.task = Some(tokio::spawn(async move { owner.run().await }));
        }
        self.wake.notify_waiters();
    }

    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.wake.notify_waiters();
    }

    async fn closed(&self) {
        loop {
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            if self.state.lock().unwrap().closed {
                return;
            }
            wake.await;
        }
    }

    pub async fn join(&self) {
        let task = self.state.lock().unwrap().task.take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    async fn run(&self) {
        loop {
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let requested = {
                let mut state = self.state.lock().unwrap();
                if state.closed {
                    return;
                }
                std::mem::take(&mut state.requested)
            };
            if !requested {
                wake.await;
                continue;
            }
            let mut attempt = 0usize;
            loop {
                if self.state.lock().unwrap().closed {
                    return;
                }
                if self.config.get().pending_addresses.is_empty() {
                    break;
                }
                let Some(bindings) = self.bindings.upgrade() else {
                    return;
                };
                // Only admission observes closed(). Once Running, retain the
                // requester through reply and acknowledgement, including exit.
                let result = native_operations::cleanup_request(
                    &self.executor,
                    bindings,
                    self.discovery.clone(),
                    self.config.clone(),
                    self.closed(),
                )
                .await;
                let remaining = self.config.get().pending_addresses.len();
                if remaining == 0 && result.is_ok() {
                    log::info!("event=temporary_cleanup outcome=completed remaining=0");
                    break;
                }
                if self.state.lock().unwrap().closed {
                    return;
                }
                let delay = [1, 2, 5, 10][attempt.min(3)];
                attempt = attempt.saturating_add(1);
                log::warn!("event=temporary_cleanup outcome=blocked remaining={remaining} retry_s={delay} reason={}",
                    result.err().map_or_else(|| "ownership_or_contention".into(), |e| super::log_value(&e.to_string())));
                tokio::select! {
                    biased;
                    () = self.closed() => return,
                    () = tokio::time::sleep(Duration::from_secs(delay)) => (),
                }
            }
        }
    }
}

// Also runs on early returns and cancellation. In-memory breadcrumbs alone
// never schedule removal, and this hook never awaits under a manager lock.
pub(super) struct ScheduleRemaining<'a> {
    pub config: &'a AppConfig,
    pub cleanup: Option<&'a Arc<TemporaryCleanup>>,
}

impl Drop for ScheduleRemaining<'_> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup {
            if !self.config.get().pending_addresses.is_empty() {
                cleanup.schedule();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        auto_adopt,
        interface::{self, AddressFuture, AddressIo, NativeAdapter},
        local_executor::{Completion, Outcome, Pending},
    };
    use super::*;
    use crate::{
        config::{AppSettings, NetworkMode, PendingAddress},
        AppError,
    };
    use std::{
        future::Future,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::oneshot;

    struct Io {
        inner: Arc<interface::address_test_io::FakeAddressIo>,
        executor: LocalExecutor,
        late_refusal: AtomicBool,
        occupant: Mutex<Option<Pending>>,
        entered: Mutex<Option<oneshot::Sender<()>>>,
        release: AsyncMutex<Option<oneshot::Receiver<()>>>,
    }

    impl AddressIo for Io {
        fn check_writes_available(&self) -> Result<(), AppError> {
            native_operations::check_writes_available_with(&self.executor)
        }
        fn native(&self) -> AddressFuture<'_, Vec<NativeAdapter>> {
            if self.late_refusal.swap(false, Ordering::SeqCst) {
                // Observation takes time in production. Model another writer
                // acquiring the slot between availability and actual submit.
                *self.occupant.lock().unwrap() = Some(
                    self.executor
                        .submit(|_| async { Completion::new(Outcome::Completed, "late_occupant") })
                        .unwrap(),
                );
            }
            self.inner.native()
        }
        fn descriptor(&self, native: &NativeAdapter) -> Option<super::super::InterfaceInfo> {
            self.inner.descriptor(native)
        }
        fn add<'a>(
            &'a self,
            _: &'a NativeAdapter,
            _: &'a str,
            _: &'a str,
        ) -> AddressFuture<'a, ()> {
            Box::pin(async { panic!("cleanup cannot create scratch addresses") })
        }
        fn remove<'a>(&'a self, adapter: &'a NativeAdapter, ip: &'a str) -> AddressFuture<'a, ()> {
            Box::pin(async move {
                if let Some(entered) = self.entered.lock().unwrap().take() {
                    entered.send(()).unwrap();
                }
                if let Some(release) = self.release.lock().await.take() {
                    release.await.unwrap();
                }
                let inner = self.inner.clone();
                let adapter = adapter.clone();
                let ip = ip.to_owned();
                native_operations::execute_with(
                    &self.executor,
                    native_operations::Operation::inventory(),
                    move |_, _| async move {
                        let result = inner.remove(&adapter, &ip).await;
                        let mut completion = Completion::new(
                            if result.is_ok() {
                                Outcome::Completed
                            } else {
                                Outcome::Uncertain
                            },
                            "fake_remove",
                        );
                        completion.observation =
                            Some(serde_json::json!({"report":{"mutated":true},"address":ip}));
                        (completion, result.map(|_| None))
                    },
                )
                .await
            })
        }
    }

    struct Fixture {
        bindings: Arc<BindingStore>,
        cleanup: Arc<TemporaryCleanup>,
        io: Arc<Io>,
        config: Arc<AppConfig>,
        executor: LocalExecutor,
        discovery: Arc<AsyncMutex<()>>,
    }

    impl Fixture {
        async fn new(persist: fn(&AppSettings) -> Result<(), AppError>) -> Self {
            let executor = LocalExecutor::for_serialized_writers();
            executor
                .reconcile(|_| async { Completion::new(Outcome::Completed, "ready") })
                .unwrap()
                .wait()
                .await
                .unwrap();
            let inner = interface::address_test_io::FakeAddressIo::new(&["192.0.2.254"]);
            let owner = inner.table.lock().unwrap()[0].mac.clone();
            let config = Arc::new(AppConfig::temporary_test_config(AppSettings {
                selected_adapter_mac: Some(owner.clone()),
                network_mode: NetworkMode::StaticAuto,
                pending_addresses: vec![PendingAddress {
                    adapter_mac: owner,
                    address: "192.0.2.254".into(),
                    prefix: 24,
                }],
                ..Default::default()
            }));
            let io = Arc::new(Io {
                inner,
                executor: executor.clone(),
                late_refusal: AtomicBool::new(false),
                occupant: Mutex::new(None),
                entered: Mutex::new(None),
                release: AsyncMutex::new(None),
            });
            let mut bindings = BindingStore::new(
                config.clone(),
                Arc::new(super::super::adapter_selector::AdapterSelector::new()),
            );
            bindings.address_io = io.clone();
            bindings.temporary_persist = persist;
            let bindings = Arc::new(bindings);
            let discovery = Arc::new(AsyncMutex::new(()));
            let cleanup = TemporaryCleanup::new(
                &bindings,
                discovery.clone(),
                config.clone(),
                executor.clone(),
            );
            assert!(bindings.cleanup.set(cleanup.clone()).is_ok());
            Self {
                bindings,
                cleanup,
                io,
                config,
                executor,
                discovery,
            }
        }

        async fn finish(self) {
            self.cleanup.close();
            self.executor.shutdown().await;
            self.cleanup.join().await;
        }
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        for _ in 0..1000 {
            if condition() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("controlled task did not reach expected state");
    }

    async fn pending<T>(mut future: std::pin::Pin<&mut impl Future<Output = T>>) {
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx)))
                .await
                .is_pending()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn early_and_late_release_refusals_schedule_the_same_scoped_cleanup() {
        for late in [false, true] {
            let fixture = Fixture::new(|_| Ok(())).await;
            let address = fixture.bindings.address_work.lock().await;
            let pending_ips = &fixture.bindings.pending_ips;
            pending_ips.write().await.push(auto_adopt::PendingIp {
                iface: "Ethernet".into(),
                ip: "192.0.2.254".parse().unwrap(),
                adoption_id: 1,
            });
            let mut early = if late {
                None
            } else {
                Some(
                    fixture
                        .executor
                        .submit(|_| async { Completion::new(Outcome::Completed, "early_occupant") })
                        .unwrap(),
                )
            };
            fixture.io.late_refusal.store(late, Ordering::SeqCst);
            let owner = fixture.config.get().pending_addresses[0]
                .adapter_mac
                .clone();
            let ops = auto_adopt::PendingAdoptOps {
                config: &fixture.config,
                adapter_mac: &owner,
                ops: super::super::AddressOps(fixture.io.as_ref(), None),
                persist: |_| Ok(()),
                cleanup: Some(&fixture.cleanup),
            };
            if late {
                auto_adopt::reconcile_pending(&ops, pending_ips, None).await;
            } else {
                auto_adopt::release_scratch(
                    &ops,
                    pending_ips,
                    "Ethernet",
                    "192.0.2.254".parse().unwrap(),
                    1,
                )
                .await;
            }
            assert_eq!(fixture.config.get().pending_addresses.len(), 1);
            assert_eq!(pending_ips.read().await.len(), 1);
            assert!(fixture.io.inner.writes.lock().unwrap().is_empty());
            assert!(fixture.cleanup.state.lock().unwrap().task.is_some());
            let mut occupant = early
                .take()
                .or_else(|| fixture.io.occupant.lock().unwrap().take())
                .unwrap();
            occupant.wait().await.unwrap();
            fixture.executor.acknowledge(occupant.id).unwrap();
            // Cleanup of existing durable ownership survives a mode change.
            fixture.config.settings.lock().unwrap().network_mode = NetworkMode::Dhcp;
            drop(address);
            until(|| {
                fixture.config.get().pending_addresses.is_empty()
                    && fixture.executor.available().is_ok()
            })
            .await;
            assert!(pending_ips.read().await.is_empty());
            assert_eq!(
                *fixture.io.inner.writes.lock().unwrap(),
                [(false, "192.0.2.254".into())]
            );
            assert!(fixture.io.inner.table.lock().unwrap()[0].ips.is_empty());
            fixture.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn schedules_coalesce_and_rearm_after_empty_without_another_task() {
        let fixture = Fixture::new(|_| Ok(())).await;
        for _ in 0..20 {
            fixture.cleanup.schedule();
        }
        let task = fixture
            .cleanup
            .state
            .lock()
            .unwrap()
            .task
            .as_ref()
            .unwrap()
            .id();
        until(|| {
            fixture.config.get().pending_addresses.is_empty()
                && fixture.executor.available().is_ok()
        })
        .await;
        // The task owns a persistent notification while quiescent, so a new
        // schedule at either side of its empty check cannot lose a wakeup.
        let row = PendingAddress {
            adapter_mac: fixture.io.inner.table.lock().unwrap()[0].mac.clone(),
            address: "192.0.2.253".into(),
            prefix: 24,
        };
        fixture
            .config
            .settings
            .lock()
            .unwrap()
            .pending_addresses
            .push(row);
        fixture.io.inner.table.lock().unwrap()[0]
            .ips
            .push(interface::IpInfo {
                address: "192.0.2.253".into(),
                prefix: 24,
                subnet: "192.0.2.0/24".into(),
            });
        fixture.cleanup.schedule();
        assert_eq!(
            fixture
                .cleanup
                .state
                .lock()
                .unwrap()
                .task
                .as_ref()
                .unwrap()
                .id(),
            task
        );
        until(|| {
            fixture.config.get().pending_addresses.is_empty()
                && fixture.executor.available().is_ok()
        })
        .await;
        assert_eq!(fixture.io.inner.writes.lock().unwrap().len(), 2);
        fixture.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_contention_and_address_timeout_acknowledge_before_retry() {
        let fixture = Fixture::new(|_| Ok(())).await;
        let discovery = fixture.discovery.lock().await;
        native_operations::cleanup_request(
            &fixture.executor,
            fixture.bindings.clone(),
            fixture.discovery.clone(),
            fixture.config.clone(),
            std::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(fixture.executor.available(), Ok(()));
        assert!(fixture.io.inner.writes.lock().unwrap().is_empty());
        drop(discovery);
        let address = fixture.bindings.address_work.lock().await;
        let mut request = Box::pin(native_operations::cleanup_request(
            &fixture.executor,
            fixture.bindings.clone(),
            fixture.discovery.clone(),
            fixture.config.clone(),
            std::future::pending(),
        ));
        pending(request.as_mut()).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        request.await.unwrap();
        assert_eq!(fixture.executor.available(), Ok(()));
        assert!(fixture.io.inner.writes.lock().unwrap().is_empty());
        drop(address);
        fixture.cleanup.schedule();
        until(|| {
            fixture.config.get().pending_addresses.is_empty()
                && fixture.executor.available().is_ok()
        })
        .await;
        fixture.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_shutdown_cancels_queued_admission_and_backoff_without_dispatch() {
        for busy in [true, false] {
            let fixture = Fixture::new(|_| Ok(())).await;
            let occupant = if busy {
                Some(
                    fixture
                        .executor
                        .submit(|_| async { Completion::new(Outcome::Completed, "occupant") })
                        .unwrap(),
                )
            } else {
                None
            };
            let discovery = fixture.discovery.lock().await;
            fixture.cleanup.schedule();
            until(|| !fixture.cleanup.state.lock().unwrap().requested).await;
            fixture.cleanup.close();
            fixture.cleanup.join().await;
            drop(discovery);
            drop(occupant);
            fixture.cleanup.schedule();
            assert!(fixture.cleanup.state.lock().unwrap().task.is_none());
            assert_eq!(fixture.config.get().pending_addresses.len(), 1);
            assert!(fixture.io.inner.writes.lock().unwrap().is_empty());
            fixture.finish().await;
        }
    }

    #[tokio::test]
    async fn admitted_cleanup_keeps_requester_through_shutdown_and_acknowledgement() {
        let fixture = Fixture::new(|_| Ok(())).await;
        let (entered, waiting) = oneshot::channel();
        let (release, finishing) = oneshot::channel();
        *fixture.io.entered.lock().unwrap() = Some(entered);
        *fixture.io.release.lock().await = Some(finishing);
        fixture.cleanup.schedule();
        waiting.await.unwrap();
        fixture.cleanup.close();
        let mut shutdown = Box::pin(fixture.executor.shutdown());
        pending(shutdown.as_mut()).await;
        release.send(()).unwrap();
        shutdown.await;
        fixture.cleanup.join().await;
        // Cancellation may refuse the nested dispatch, but never abandons the
        // transaction requester or clears the remaining durable ownership.
        assert!(fixture.executor.retained().is_none());
        assert_eq!(fixture.config.get().pending_addresses.len(), 1);
        assert!(fixture.io.inner.writes.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn conflicts_replaced_adapters_and_new_claims_preserve_removal_authority() {
        for conflict in 0..5 {
            let fixture = Fixture::new(|_| Ok(())).await;
            match conflict {
                0 => fixture.io.inner.table.lock().unwrap()[0].ips[0].prefix = 25,
                1 => fixture.io.inner.table.lock().unwrap()[0].index += 1,
                2 => fixture.io.inner.table.lock().unwrap().clear(),
                3 => {
                    fixture
                        .config
                        .settings
                        .lock()
                        .unwrap()
                        .pending_addresses
                        .clear();
                }
                _ => fixture.io.inner.table.lock().unwrap()[0].ips.clear(),
            }
            native_operations::cleanup_request(
                &fixture.executor,
                fixture.bindings.clone(),
                fixture.discovery.clone(),
                fixture.config.clone(),
                std::future::pending(),
            )
            .await
            .ok();
            assert!(fixture.io.inner.writes.lock().unwrap().is_empty());
            assert_eq!(
                fixture.config.get().pending_addresses.len(),
                usize::from(conflict < 3)
            );
            fixture.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn native_and_persistence_failures_keep_rows_and_uncertain_barriers() {
        for save_failure in [false, true] {
            let fixture = Fixture::new(if save_failure {
                |_| Err(AppError::Config("injected save failure".into()))
            } else {
                |_| Ok(())
            })
            .await;
            if !save_failure {
                *fixture.io.inner.effect.lock().unwrap() =
                    interface::address_test_io::Effect::ErrorAfter;
            }
            assert!(native_operations::cleanup_request(
                &fixture.executor,
                fixture.bindings.clone(),
                fixture.discovery.clone(),
                fixture.config.clone(),
                std::future::pending()
            )
            .await
            .is_err());
            assert_eq!(fixture.config.get().pending_addresses.len(), 1);
            assert_eq!(
                fixture.executor.retained().unwrap().1.outcome,
                Outcome::Uncertain
            );
            assert!(fixture.io.inner.table.lock().unwrap()[0].ips.is_empty());
            fixture.finish().await;
        }
    }
}
