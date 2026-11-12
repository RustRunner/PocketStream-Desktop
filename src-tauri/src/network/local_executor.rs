//! Process-local ownership across cancellation of a requesting future.
//! One admitted operation, a small admission queue and one retained completion.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{oneshot, Notify};
use tokio::time::Instant;

use super::native_runner::Cancellation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Completed,
    Failed,
    Canceled,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Completion {
    pub outcome: Outcome,
    pub step: &'static str,
    // Bounded structured native facts stay with a completion even after the
    // requesting future and its response channel have gone away.
    pub observation: Option<serde_json::Value>,
}

impl Completion {
    pub fn new(outcome: Outcome, step: &'static str) -> Self {
        Self {
            outcome,
            step,
            observation: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AdmissionError {
    Busy,
    ReconciliationRequired,
    ShuttingDown,
    Superseded,
    TimedOut,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum AdmissionClass {
    Cleanup,
    User,
    Policy,
}

impl AdmissionClass {
    fn name(self) -> &'static str {
        match self {
            Self::Cleanup => "cleanup",
            Self::User => "user",
            Self::Policy => "policy",
        }
    }

    fn priority(self, elapsed: Duration) -> u64 {
        let base = match self {
            Self::Cleanup => 0,
            Self::User => 1,
            Self::Policy => 2,
        };
        (base + elapsed.as_secs() / 10).min(2)
    }
}

pub(super) struct Admission {
    pub class: AdmissionClass,
    pub wait: Duration,
    pub managed: bool,
}

struct Waiter {
    sequence: u64,
    class: AdmissionClass,
    enqueued: Instant,
    deadline: Instant,
}

enum Phase {
    RecoveryRequired,
    Idle,
    Running {
        id: u64,
        cancel: Cancellation,
        managed: bool,
        requester: bool,
    },
    Retained {
        id: u64,
        result: Completion,
        requester: bool,
    },
}

struct State {
    phase: Phase,
    next_id: u64,
    shutdown: bool,
    next_waiter: u64,
    waiters: VecDeque<Waiter>,
}

impl State {
    #[cfg(feature = "qualification-r6")]
    fn qualification_observe(&self, phase: &str) {
        let (kind, id, requester, outcome, step) = match &self.phase {
            Phase::RecoveryRequired => ("recovery_required", 0, false, None, "-"),
            Phase::Idle => ("idle", 0, false, None, "-"),
            Phase::Running { id, requester, .. } => ("running", *id, *requester, None, "-"),
            Phase::Retained {
                id,
                requester,
                result,
            } => (
                "retained",
                *id,
                *requester,
                Some(result.outcome),
                result.step,
            ),
        };
        log::info!("event=qualification_r6_executor phase={phase} state={kind} id={id} requester={requester} outcome={outcome:?} step={step} shutdown={} waiters={:?}", self.shutdown, self.waiters.iter().map(|w| (w.sequence, w.class.name())).collect::<Vec<_>>());
    }

    fn prune(&mut self, now: Instant) {
        self.waiters.retain(|w| w.deadline > now);
    }

    fn available(&mut self) -> Result<(), AdmissionError> {
        if self.shutdown {
            return Err(AdmissionError::ShuttingDown);
        }
        self.prune(Instant::now());
        match &self.phase {
            Phase::Idle if self.waiters.is_empty() => Ok(()),
            Phase::Idle | Phase::Running { .. } => Err(AdmissionError::Busy),
            Phase::Retained {
                result,
                requester: true,
                ..
            } if result.outcome != Outcome::Uncertain => Err(AdmissionError::Busy),
            _ => Err(AdmissionError::ReconciliationRequired),
        }
    }

    fn best(&self, now: Instant) -> Option<u64> {
        self.waiters
            .iter()
            .min_by_key(|w| {
                (
                    std::cmp::Reverse(w.class.priority(now - w.enqueued)),
                    w.sequence,
                )
            })
            .map(|w| w.sequence)
    }
}

struct Shared {
    state: Mutex<State>,
    terminal: Notify,
    admission: Notify,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
pub(super) struct LocalExecutor(Arc<Shared>);

pub(super) struct Pending {
    pub id: u64,
    response: oneshot::Receiver<Completion>,
    cancel: Cancellation,
    shared: Arc<Shared>,
}

impl Pending {
    pub async fn wait(&mut self) -> Result<Completion, oneshot::error::RecvError> {
        (&mut self.response).await
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // A task abort drops this ticket, never the worker/job or its barrier.
        self.cancel.request();
        let mut state = self.shared.state.lock().unwrap();
        match &mut state.phase {
            Phase::Running { id, requester, .. } | Phase::Retained { id, requester, .. }
                if *id == self.id =>
            {
                *requester = false
            }
            _ => (),
        }
        #[cfg(feature = "qualification-r6")]
        state.qualification_observe("requester_drop");
        self.shared.admission.notify_waiters();
    }
}

// The future owns this guard, including while it is awake but has not polled.
// Queue depth in decision logs is the number of other live waiters, after removal.
struct WaiterGuard {
    shared: Arc<Shared>,
    sequence: u64,
    class: AdmissionClass,
    enqueued: Instant,
    armed: bool,
}

impl WaiterGuard {
    fn finish(&mut self, state: &mut State, outcome: &str) {
        state.waiters.retain(|w| w.sequence != self.sequence);
        state.prune(Instant::now());
        self.armed = false;
        log::info!(
            "event=native_admission class={} outcome={} waited_ms={} queue_depth={}",
            self.class.name(),
            outcome,
            self.enqueued.elapsed().as_millis(),
            state.waiters.len()
        );
        self.shared.admission.notify_waiters();
        #[cfg(feature = "qualification-r6-queued")]
        if matches!(self.class, AdmissionClass::Policy) && outcome == "superseded" {
            super::native_operations::qualification_r6_release_occupant();
        }
    }
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        if self.armed {
            let shared = self.shared.clone();
            self.finish(&mut shared.state.lock().unwrap(), "superseded");
        }
    }
}

impl LocalExecutor {
    // Admission below fences every native writer. Higher-level transactions
    // keep their existing address_work lock; reacquiring it here would deadlock.
    pub fn for_serialized_writers() -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State {
                phase: Phase::RecoveryRequired,
                next_id: 0,
                shutdown: false,
                next_waiter: 0,
                waiters: VecDeque::new(),
            }),
            terminal: Notify::new(),
            admission: Notify::new(),
            worker: Mutex::new(None),
        }))
    }

    pub async fn admit<F, Fut>(
        &self,
        admission: Admission,
        abort: impl Future<Output = ()>,
        work: F,
    ) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        let enqueued = Instant::now();
        let deadline = enqueued + admission.wait;
        let sequence = {
            let mut state = self.0.state.lock().unwrap();
            state.next_waiter = state.next_waiter.checked_add(1).expect("waiter counter");
            let sequence = state.next_waiter;
            state.waiters.push_back(Waiter {
                sequence,
                class: admission.class,
                enqueued,
                deadline,
            });
            sequence
        };
        let mut guard = WaiterGuard {
            shared: self.0.clone(),
            sequence,
            class: admission.class,
            enqueued,
            armed: true,
        };
        tokio::pin!(abort);
        let expiry = tokio::time::sleep_until(deadline);
        tokio::pin!(expiry);
        #[cfg(feature = "qualification-r6")]
        let mut observed_wait = false;
        loop {
            let notified = self.0.admission.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            // Last abort poll before the atomic transition. A signal racing after
            // this poll may lose and is then post-admission cancellation.
            let refusal = tokio::select! {
                biased;
                () = &mut abort => Some(AdmissionError::Superseded),
                () = &mut expiry => Some(AdmissionError::TimedOut),
                () = std::future::ready(()) => None,
            };
            let recheck_at = {
                let mut state = self.0.state.lock().unwrap();
                let now = Instant::now();
                let refusal = refusal.or_else(|| {
                    if state.shutdown {
                        Some(AdmissionError::ShuttingDown)
                    } else if now >= deadline {
                        Some(AdmissionError::TimedOut)
                    } else if matches!(&state.phase, Phase::Retained { result, requester, .. }
                        if result.outcome == Outcome::Uncertain || !requester)
                    {
                        Some(AdmissionError::ReconciliationRequired)
                    } else {
                        None
                    }
                });
                if let Some(error) = refusal {
                    guard.finish(
                        &mut state,
                        match error {
                            AdmissionError::Superseded => "superseded",
                            AdmissionError::TimedOut => "timed_out",
                            AdmissionError::ShuttingDown => "shutting_down",
                            _ => "reconciliation_required",
                        },
                    );
                    return Err(error);
                }
                state.prune(now);
                if matches!(state.phase, Phase::Idle) && state.best(now) == Some(sequence) {
                    guard.finish(&mut state, "admitted");
                    return Ok(self.start_locked(&mut state, false, admission.managed, work));
                }
                #[cfg(feature = "qualification-r6")]
                if !observed_wait {
                    state.qualification_observe("awaiting_admission");
                    observed_wait = true;
                }
                // An Idle queue must not depend on an expired owner's next
                // poll. Other waiting futures recheck at the earliest existing
                // admission deadline; this never grants or reserves the slot.
                if matches!(state.phase, Phase::Idle) {
                    state.waiters.iter().map(|w| w.deadline).min()
                } else {
                    None
                }
            };
            tokio::select! {
                biased;
                () = &mut abort => {
                    guard.finish(&mut self.0.state.lock().unwrap(), "superseded");
                    return Err(AdmissionError::Superseded);
                }
                () = &mut expiry => {
                    guard.finish(&mut self.0.state.lock().unwrap(), "timed_out");
                    return Err(AdmissionError::TimedOut);
                }
                () = notified => (),
                () = async {
                    if let Some(at) = recheck_at { tokio::time::sleep_until(at).await; }
                    else { std::future::pending::<()>().await; }
                } => (),
            }
        }
    }

    pub fn submit<F, Fut>(&self, work: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(false, false, None, work)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Keep the fail-fast managed entry for lock-holding callers; waiting transactions use admit"
        )
    )]
    pub fn submit_managed<F, Fut>(&self, work: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(false, true, None, work)
    }

    pub fn reconcile<F, Fut>(&self, observe: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(true, true, None, observe)
    }

    pub fn reconcile_retained<F, Fut>(&self, id: u64, observe: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(true, true, Some(id), observe)
    }

    fn start<F, Fut>(
        &self,
        recovery: bool,
        managed: bool,
        retained_id: Option<u64>,
        work: F,
    ) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        let mut state = self.0.state.lock().unwrap();
        if state.shutdown {
            return Err(AdmissionError::ShuttingDown);
        }
        if recovery {
            if matches!(state.phase, Phase::Running { .. }) {
                return Err(AdmissionError::Busy);
            }
        } else {
            state.available()?;
        }
        if let Some(expected) = retained_id {
            if !matches!(&state.phase, Phase::Retained { id, result, .. } if *id == expected && result.outcome == Outcome::Uncertain)
            {
                return Err(AdmissionError::ReconciliationRequired);
            }
        }
        Ok(self.start_locked(&mut state, recovery, managed, work))
    }

    fn start_locked<F, Fut>(
        &self,
        state: &mut State,
        recovery: bool,
        managed: bool,
        work: F,
    ) -> Pending
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        state.next_id = state.next_id.checked_add(1).expect("operation counter");
        let id = state.next_id;
        let cancel = Cancellation::default();
        state.phase = Phase::Running {
            id,
            cancel: cancel.clone(),
            managed,
            requester: true,
        };
        #[cfg(feature = "qualification-r6")]
        state.qualification_observe("admitted");
        let (tx, response) = oneshot::channel();
        let shared = self.0.clone();
        let signal = cancel.clone();
        // This task owns admission, the transaction, child runner and native
        // observation before the requesting task can receive its ticket.
        let worker = tokio::spawn(async move {
            let result = tokio::spawn(async move { work(signal).await })
                .await
                .unwrap_or_else(|_| Completion::new(Outcome::Uncertain, "worker_panicked"));
            Self::finish(shared, id, recovery, result.clone());
            let _ = tx.send(result); // Losing this reply never loses completion.
        });
        *self.0.worker.lock().unwrap() = Some(worker);
        Pending {
            id,
            response,
            cancel,
            shared: self.0.clone(),
        }
    }

    fn finish(shared: Arc<Shared>, id: u64, recovery: bool, result: Completion) {
        let mut state = shared.state.lock().unwrap();
        let requester = match state.phase {
            Phase::Running {
                id: running,
                requester,
                ..
            } if running == id => requester,
            _ => panic!("completion must match running operation"),
        };
        #[cfg(feature = "qualification-r5")]
        if result.step.starts_with("firewall") {
            log::info!("event=qualification_r5_completion id={id} recovery={recovery} requester={requester} result={result:?}");
        }
        state.phase = if recovery && result.outcome == Outcome::Completed {
            Phase::Idle
        } else {
            Phase::Retained {
                id,
                result,
                requester,
            }
        };
        #[cfg(feature = "qualification-r6")]
        state.qualification_observe("completion_accounted");
        shared.terminal.notify_waiters();
        shared.admission.notify_waiters();
    }

    pub fn retained(&self) -> Option<(u64, Completion)> {
        match &self.0.state.lock().unwrap().phase {
            Phase::Retained { id, result, .. } => Some((*id, result.clone())),
            _ => None,
        }
    }

    pub fn available(&self) -> Result<(), AdmissionError> {
        self.0.state.lock().unwrap().available()
    }

    #[cfg(feature = "qualification-r6")]
    pub fn qualification_observe(&self, phase: &str) {
        self.0.state.lock().unwrap().qualification_observe(phase);
    }

    pub fn acknowledge(&self, id: u64) -> Result<(), AdmissionError> {
        let mut state = self.0.state.lock().unwrap();
        match &state.phase {
            Phase::Retained {
                id: current,
                result,
                requester: true,
            } if *current == id && result.outcome != Outcome::Uncertain => {
                #[cfg(feature = "qualification-r5")]
                log::info!(
                    "event=qualification_r5_acknowledge id={id} outcome={:?}",
                    result.outcome
                );
                state.phase = Phase::Idle;
                self.0.admission.notify_waiters();
                Ok(())
            }
            _ => Err(AdmissionError::ReconciliationRequired),
        }
    }

    #[cfg(test)]
    pub async fn wait_terminal(&self) {
        self.wait(true).await;
    }

    pub async fn wait_writer(&self) {
        // Managed transactions own the manager's existing locks themselves. A
        // watcher holding one of those locks must not wait for their acquisition.
        // Ordinary writes remain blocked, and shutdown still joins all work.
        self.wait(false).await;
    }

    async fn wait(&self, include_managed: bool) {
        loop {
            let notified = self.0.terminal.notified();
            // Register before inspecting state to avoid missing the transition.
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !matches!(self.0.state.lock().unwrap().phase, Phase::Running { managed, .. } if include_managed || !managed)
            {
                return;
            }
            notified.await;
        }
    }

    pub async fn shutdown(&self) {
        {
            let mut state = self.0.state.lock().unwrap();
            state.shutdown = true;
            #[cfg(feature = "qualification-r6")]
            state.qualification_observe("shutdown_requested");
            state.waiters.clear();
            self.0.admission.notify_waiters();
            if let Phase::Running { cancel, .. } = &state.phase {
                cancel.request();
            }
        }
        let worker = self.0.worker.lock().unwrap().take();
        if let Some(worker) = worker {
            let _ = worker.await;
        }
        #[cfg(feature = "qualification-r6")]
        self.qualification_observe("shutdown_joined");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn ready() -> LocalExecutor {
        let executor = LocalExecutor::for_serialized_writers();
        executor
            .reconcile(|_| async { Completion::new(Outcome::Completed, "ready") })
            .unwrap()
            .wait()
            .await
            .unwrap();
        executor
    }

    fn admission(class: AdmissionClass) -> Admission {
        Admission {
            class,
            wait: Duration::from_secs(60),
            managed: false,
        }
    }

    async fn queued<T>(future: std::pin::Pin<&mut impl Future<Output = T>>) {
        let mut future = future;
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx)))
                .await
                .is_pending()
        );
    }

    async fn acknowledge(executor: &LocalExecutor, ticket: &mut Pending) {
        ticket.wait().await.unwrap();
        executor.acknowledge(ticket.id).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn fifo_priority_no_barging_and_atomic_selection() {
        let executor = LocalExecutor::for_serialized_writers();
        let mut cleanup = Box::pin(executor.admit(
            admission(AdmissionClass::Cleanup),
            std::future::pending(),
            |_| async { Completion::new(Outcome::Completed, "cleanup") },
        ));
        let mut user1 = Box::pin(executor.admit(
            admission(AdmissionClass::User),
            std::future::pending(),
            |_| async { Completion::new(Outcome::Completed, "user1") },
        ));
        let mut user2 = Box::pin(executor.admit(
            admission(AdmissionClass::User),
            std::future::pending(),
            |_| async { Completion::new(Outcome::Completed, "user2") },
        ));
        let mut policy = Box::pin(executor.admit(
            admission(AdmissionClass::Policy),
            std::future::pending(),
            |_| async { Completion::new(Outcome::Completed, "policy") },
        ));
        queued(cleanup.as_mut()).await;
        queued(user1.as_mut()).await;
        queued(user2.as_mut()).await;
        queued(policy.as_mut()).await;
        executor
            .reconcile(|_| async { Completion::new(Outcome::Completed, "ready") })
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(executor.available(), Err(AdmissionError::Busy));
        assert!(matches!(
            executor.submit(|_| async { unreachable!() }),
            Err(AdmissionError::Busy)
        ));
        assert!(matches!(
            executor.submit_managed(|_| async { unreachable!() }),
            Err(AdmissionError::Busy)
        ));
        queued(user1.as_mut()).await;
        let mut ticket = policy.await.unwrap();
        assert_eq!(ticket.wait().await.unwrap().step, "policy");
        // Retained live completion is Busy, and queued work stays queued.
        queued(user1.as_mut()).await;
        executor.acknowledge(ticket.id).unwrap();
        let mut ticket = user1.await.unwrap();
        assert_eq!(ticket.wait().await.unwrap().step, "user1");
        executor.acknowledge(ticket.id).unwrap();
        let mut ticket = user2.await.unwrap();
        acknowledge(&executor, &mut ticket).await;
        let mut ticket = cleanup.await.unwrap();
        acknowledge(&executor, &mut ticket).await;
        assert_eq!(executor.available(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_lazy_aging_uses_original_sequence_for_ties() {
        let executor = LocalExecutor::for_serialized_writers();
        let mut cleanup = Box::pin(executor.admit(
            admission(AdmissionClass::Cleanup),
            std::future::pending(),
            |_| async { Completion::new(Outcome::Completed, "cleanup") },
        ));
        queued(cleanup.as_mut()).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        let mut user = Box::pin(executor.admit(
            admission(AdmissionClass::User),
            std::future::pending(),
            |_| async { Completion::new(Outcome::Completed, "user") },
        ));
        queued(user.as_mut()).await;
        assert_eq!(
            executor.0.state.lock().unwrap().best(Instant::now()),
            Some(1)
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        let mut policy = Box::pin(executor.admit(
            admission(AdmissionClass::Policy),
            std::future::pending(),
            |_| async { Completion::new(Outcome::Completed, "policy") },
        ));
        queued(policy.as_mut()).await;
        assert_eq!(
            executor.0.state.lock().unwrap().best(Instant::now()),
            Some(1)
        );
        executor
            .reconcile(|_| async { Completion::new(Outcome::Completed, "ready") })
            .unwrap()
            .wait()
            .await
            .unwrap();
        queued(policy.as_mut()).await;
        let mut ticket = cleanup.await.unwrap();
        acknowledge(&executor, &mut ticket).await;
        queued(policy.as_mut()).await;
        let mut ticket = user.await.unwrap();
        acknowledge(&executor, &mut ticket).await;
        let mut ticket = policy.await.unwrap();
        acknowledge(&executor, &mut ticket).await;
    }

    #[tokio::test(start_paused = true)]
    async fn drop_after_wake_and_expired_unpolled_entries_never_reserve_idle() {
        let executor = LocalExecutor::for_serialized_writers();
        let mut first = Box::pin(executor.admit(
            admission(AdmissionClass::Policy),
            std::future::pending(),
            |_| async { unreachable!() },
        ));
        let mut next = Box::pin(executor.admit(
            admission(AdmissionClass::User),
            std::future::pending(),
            |_| async { Completion::new(Outcome::Completed, "next") },
        ));
        queued(first.as_mut()).await;
        queued(next.as_mut()).await;
        executor
            .reconcile(|_| async { Completion::new(Outcome::Completed, "ready") })
            .unwrap()
            .wait()
            .await
            .unwrap();
        drop(first); // Woken, but never polled to claim.
        let mut ticket = next.await.unwrap();
        acknowledge(&executor, &mut ticket).await;
        let mut expired = Box::pin(executor.admit(
            Admission {
                wait: Duration::from_secs(1),
                ..admission(AdmissionClass::Policy)
            },
            std::future::pending(),
            |_| async { unreachable!() },
        ));
        let mut occupant = executor
            .submit(|_| async { Completion::new(Outcome::Completed, "occupant") })
            .unwrap();
        queued(expired.as_mut()).await;
        acknowledge(&executor, &mut occupant).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(executor.available(), Ok(()));
        assert!(matches!(expired.await, Err(AdmissionError::TimedOut)));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_waiter_wakes_for_expiry_without_the_expired_owner_polling() {
        let executor = LocalExecutor::for_serialized_writers();
        let mut expired = Box::pin(executor.admit(
            Admission {
                wait: Duration::from_secs(1),
                ..admission(AdmissionClass::Policy)
            },
            std::future::pending(),
            |_| async { unreachable!() },
        ));
        queued(expired.as_mut()).await;
        let owned = executor.clone();
        let next = tokio::spawn(async move {
            owned
                .admit(
                    admission(AdmissionClass::User),
                    std::future::pending(),
                    |_| async { Completion::new(Outcome::Completed, "next") },
                )
                .await
                .unwrap()
        });
        while executor.0.state.lock().unwrap().waiters.len() != 2 {
            tokio::task::yield_now().await;
        }
        executor
            .reconcile(|_| async { Completion::new(Outcome::Completed, "ready") })
            .unwrap()
            .wait()
            .await
            .unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let mut ticket = next.await.unwrap();
        acknowledge(&executor, &mut ticket).await;
        assert!(matches!(expired.await, Err(AdmissionError::TimedOut)));
        assert_eq!(executor.available(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn ready_abort_and_expiry_win_idle_and_simultaneous_availability() {
        let executor = ready().await;
        assert!(matches!(
            executor
                .admit(
                    admission(AdmissionClass::Policy),
                    std::future::ready(()),
                    |_| async { unreachable!() }
                )
                .await,
            Err(AdmissionError::Superseded)
        ));
        assert!(matches!(
            executor
                .admit(
                    Admission {
                        wait: Duration::ZERO,
                        ..admission(AdmissionClass::Policy)
                    },
                    std::future::ready(()),
                    |_| async { unreachable!() }
                )
                .await,
            Err(AdmissionError::Superseded)
        ));
        assert!(matches!(
            executor
                .admit(
                    Admission {
                        wait: Duration::ZERO,
                        ..admission(AdmissionClass::Policy)
                    },
                    std::future::pending(),
                    |_| async { unreachable!() }
                )
                .await,
            Err(AdmissionError::TimedOut)
        ));
        let mut occupant = executor
            .submit(|_| async { Completion::new(Outcome::Completed, "occupant") })
            .unwrap();
        let (abort, aborted) = oneshot::channel();
        let mut waiter = Box::pin(executor.admit(
            admission(AdmissionClass::User),
            async {
                let _ = aborted.await;
            },
            |_| async { unreachable!() },
        ));
        queued(waiter.as_mut()).await;
        acknowledge(&executor, &mut occupant).await;
        abort.send(()).unwrap();
        assert!(matches!(waiter.await, Err(AdmissionError::Superseded)));
        assert_eq!(executor.available(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn live_acknowledgement_has_no_grace_timer_and_drop_creates_barrier() {
        let executor = ready().await;
        let mut ticket = executor
            .submit(|_| async { Completion::new(Outcome::Completed, "live") })
            .unwrap();
        ticket.wait().await.unwrap();
        tokio::time::advance(Duration::from_secs(25)).await;
        assert_eq!(executor.available(), Err(AdmissionError::Busy));
        let mut waiter = Box::pin(executor.admit(
            admission(AdmissionClass::User),
            std::future::pending(),
            |_| async { unreachable!() },
        ));
        queued(waiter.as_mut()).await;
        drop(ticket);
        assert_eq!(
            executor.available(),
            Err(AdmissionError::ReconciliationRequired)
        );
        assert!(matches!(
            waiter.await,
            Err(AdmissionError::ReconciliationRequired)
        ));
        tokio::time::advance(Duration::from_secs(100)).await;
        assert_eq!(
            executor.available(),
            Err(AdmissionError::ReconciliationRequired)
        );
    }

    #[tokio::test]
    async fn running_abandonment_and_stale_drop_preserve_matching_ids_only() {
        let executor = ready().await;
        let (release, waiting) = oneshot::channel();
        let ticket = executor
            .submit(|_| async {
                waiting.await.unwrap();
                Completion::new(Outcome::Completed, "abandoned")
            })
            .unwrap();
        let mut queued_call = Box::pin(executor.admit(
            admission(AdmissionClass::User),
            std::future::pending(),
            |_| async { unreachable!() },
        ));
        queued(queued_call.as_mut()).await;
        drop(queued_call);
        assert_eq!(executor.available(), Err(AdmissionError::Busy));
        drop(ticket);
        assert_eq!(executor.available(), Err(AdmissionError::Busy));
        release.send(()).unwrap();
        executor.wait_terminal().await;
        assert_eq!(
            executor.available(),
            Err(AdmissionError::ReconciliationRequired)
        );
        let mut recovery = executor
            .reconcile(|_| async { Completion::new(Outcome::Completed, "recovered") })
            .unwrap();
        recovery.wait().await.unwrap();
        let mut newer = executor
            .submit(|_| async { Completion::new(Outcome::Completed, "newer") })
            .unwrap();
        drop(recovery);
        newer.wait().await.unwrap();
        assert_eq!(executor.available(), Err(AdmissionError::Busy));
        executor.acknowledge(newer.id).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn startup_failure_and_uncertain_results_refuse_waiters_without_dispatch() {
        let executor = LocalExecutor::for_serialized_writers();
        let mut waiter = Box::pin(executor.admit(
            admission(AdmissionClass::Policy),
            std::future::pending(),
            |_| async { unreachable!() },
        ));
        queued(waiter.as_mut()).await;
        let mut startup = executor
            .reconcile(|_| async { Completion::new(Outcome::Uncertain, "failed_startup") })
            .unwrap();
        startup.wait().await.unwrap();
        assert!(matches!(
            waiter.await,
            Err(AdmissionError::ReconciliationRequired)
        ));
        assert_eq!(
            executor.acknowledge(startup.id),
            Err(AdmissionError::ReconciliationRequired)
        );
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(
            executor.available(),
            Err(AdmissionError::ReconciliationRequired)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn notifications_do_not_reset_deadline_and_shutdown_joins_without_queue_polling() {
        let executor = ready().await;
        let (release, waiting) = oneshot::channel();
        let occupant = executor
            .submit(|cancel| async move {
                waiting.await.unwrap();
                assert!(cancel.requested());
                Completion::new(Outcome::Completed, "stopped")
            })
            .unwrap();
        let mut waiter = Box::pin(executor.admit(
            Admission {
                wait: Duration::from_secs(15),
                ..admission(AdmissionClass::User)
            },
            std::future::pending(),
            |_| async { unreachable!() },
        ));
        queued(waiter.as_mut()).await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(4)).await;
            executor.0.admission.notify_waiters();
            queued(waiter.as_mut()).await;
        }
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(matches!(waiter.await, Err(AdmissionError::TimedOut)));
        let mut queued_shutdown = Box::pin(executor.admit(
            admission(AdmissionClass::Policy),
            std::future::pending(),
            |_| async { unreachable!() },
        ));
        queued(queued_shutdown.as_mut()).await;
        let mut shutdown = Box::pin(executor.shutdown());
        queued(shutdown.as_mut()).await;
        release.send(()).unwrap();
        shutdown.await;
        assert!(matches!(
            queued_shutdown.await,
            Err(AdmissionError::ShuttingDown)
        ));
        assert_eq!(executor.available(), Err(AdmissionError::ShuttingDown));
        assert!(executor.retained().is_some());
        drop(occupant);
    }
    #[tokio::test]
    async fn conditional_reconcile_checks_retained_id_uncertainty_running_and_shutdown() {
        let executor = LocalExecutor::for_serialized_writers();
        let mut ticket = executor
            .reconcile(|_| async { Completion::new(Outcome::Uncertain, "firewall_policy") })
            .unwrap();
        let original = ticket.id;
        ticket.wait().await.unwrap();
        assert!(matches!(
            executor.reconcile_retained(original + 1, |_| async { unreachable!() }),
            Err(AdmissionError::ReconciliationRequired)
        ));
        let (release, wait) = oneshot::channel();
        let ticket = executor
            .reconcile_retained(original, |_| async move {
                wait.await.unwrap();
                Completion::new(Outcome::Uncertain, "firewall_policy")
            })
            .unwrap();
        assert!(matches!(
            executor.reconcile_retained(original, |_| async { unreachable!() }),
            Err(AdmissionError::Busy)
        ));
        drop(ticket);
        release.send(()).unwrap();
        executor.wait_terminal().await;
        let (new_id, retained) = executor.retained().unwrap();
        assert_ne!(new_id, original);
        assert_eq!(retained.outcome, Outcome::Uncertain);
        assert!(matches!(
            executor.reconcile_retained(original, |_| async { unreachable!() }),
            Err(AdmissionError::ReconciliationRequired)
        ));
        assert_eq!(
            executor.acknowledge(new_id),
            Err(AdmissionError::ReconciliationRequired)
        );
        executor
            .reconcile_retained(new_id, |_| async {
                Completion::new(Outcome::Completed, "verified")
            })
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(executor.available(), Ok(()));
        assert!(matches!(
            executor.reconcile_retained(new_id, |_| async { unreachable!() }),
            Err(AdmissionError::ReconciliationRequired)
        ));
        let mut ticket = executor
            .submit(|_| async { Completion::new(Outcome::Failed, "ordinary") })
            .unwrap();
        let ordinary_id = ticket.id;
        ticket.wait().await.unwrap();
        assert!(matches!(
            executor.reconcile_retained(ordinary_id, |_| async { unreachable!() }),
            Err(AdmissionError::ReconciliationRequired)
        ));
        assert_eq!(executor.acknowledge(ordinary_id), Ok(()));
        executor.shutdown().await;
        assert!(matches!(
            executor.reconcile_retained(ordinary_id, |_| async { unreachable!() }),
            Err(AdmissionError::ShuttingDown)
        ));
    }

    #[tokio::test]
    async fn recovery_drain_does_not_wait_for_a_manager_lock_held_by_its_caller() {
        let executor = LocalExecutor::for_serialized_writers();
        let (release, wait) = oneshot::channel();
        let mut ticket = executor
            .reconcile(|_| async move {
                let _ = wait.await;
                Completion::new(Outcome::Completed, "startup_reconciled")
            })
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            executor.wait_writer(),
        )
        .await
        .unwrap();
        assert_eq!(executor.available(), Err(AdmissionError::Busy));
        release.send(()).unwrap();
        ticket.wait().await.unwrap();
        assert_eq!(executor.available(), Ok(()));
    }
}
