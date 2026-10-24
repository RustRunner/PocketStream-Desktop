//! Process-local ownership, qualified before wiring any production writer.
//! One admitted operation and one retained completion; no admission queue.

use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, Notify, OwnedMutexGuard};

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
}

impl Completion {
    pub fn new(outcome: Outcome, step: &'static str) -> Self {
        Self { outcome, step }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AdmissionError {
    Busy,
    ReconciliationRequired,
    ShuttingDown,
}

enum Phase {
    RecoveryRequired,
    Idle,
    Running { id: u64, cancel: Cancellation },
    Retained { id: u64, result: Completion },
}

struct State {
    phase: Phase,
    next_id: u64,
    shutdown: bool,
}

struct Shared {
    state: Mutex<State>,
    terminal: Notify,
    // Reuses the manager's existing address serialization lock on integration.
    serialization: Arc<tokio::sync::Mutex<()>>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
pub(super) struct LocalExecutor(Arc<Shared>);

pub(super) struct Pending {
    pub id: u64,
    response: oneshot::Receiver<Completion>,
    cancel: Cancellation,
}

impl Pending {
    pub async fn wait(mut self) -> Result<Completion, oneshot::error::RecvError> {
        (&mut self.response).await
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // A task abort drops this ticket, never the worker/job or its barrier.
        self.cancel.request();
    }
}

impl LocalExecutor {
    pub fn new(serialization: Arc<tokio::sync::Mutex<()>>) -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State {
                phase: Phase::RecoveryRequired,
                next_id: 0,
                shutdown: false,
            }),
            terminal: Notify::new(),
            serialization,
            worker: Mutex::new(None),
        }))
    }

    pub fn submit<F, Fut>(&self, work: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(false, work)
    }

    pub fn reconcile<F, Fut>(&self, observe: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(true, observe)
    }

    fn start<F, Fut>(&self, recovery: bool, work: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        let mut state = self.0.state.lock().unwrap();
        if state.shutdown {
            return Err(AdmissionError::ShuttingDown);
        }
        match (&state.phase, recovery) {
            (Phase::Running { .. }, _) => return Err(AdmissionError::Busy),
            (Phase::Idle, _) | (_, true) => (),
            _ => return Err(AdmissionError::ReconciliationRequired),
        }
        let serial = self
            .0
            .serialization
            .clone()
            .try_lock_owned()
            .map_err(|_| AdmissionError::Busy)?;
        state.next_id = state.next_id.checked_add(1).expect("operation counter");
        let id = state.next_id;
        let cancel = Cancellation::default();
        state.phase = Phase::Running {
            id,
            cancel: cancel.clone(),
        };
        let (tx, response) = oneshot::channel();
        let shared = self.0.clone();
        let signal = cancel.clone();
        // This task owns admission, the serial guard, child runner and native
        // observation before the requesting task can receive its ticket.
        let worker = tokio::spawn(async move {
            let result = tokio::spawn(async move { work(signal).await })
                .await
                .unwrap_or_else(|_| Completion::new(Outcome::Uncertain, "worker_panicked"));
            Self::finish(shared, serial, id, recovery, result.clone());
            let _ = tx.send(result); // Losing this reply never loses completion.
        });
        *self.0.worker.lock().unwrap() = Some(worker);
        Ok(Pending {
            id,
            response,
            cancel,
        })
    }

    fn finish(
        shared: Arc<Shared>,
        serial: OwnedMutexGuard<()>,
        id: u64,
        recovery: bool,
        result: Completion,
    ) {
        let mut state = shared.state.lock().unwrap();
        assert!(matches!(state.phase, Phase::Running { id: running, .. } if running == id));
        drop(serial); // Actual work/observation drained before publishing idle.
        state.phase = if recovery && result.outcome == Outcome::Completed {
            Phase::Idle
        } else {
            Phase::Retained { id, result }
        };
        shared.terminal.notify_waiters();
    }

    pub fn retained(&self) -> Option<(u64, Completion)> {
        match &self.0.state.lock().unwrap().phase {
            Phase::Retained { id, result } => Some((*id, result.clone())),
            _ => None,
        }
    }

    pub fn acknowledge(&self, id: u64) -> Result<(), AdmissionError> {
        let mut state = self.0.state.lock().unwrap();
        match &state.phase {
            Phase::Retained {
                id: current,
                result,
            } if *current == id && result.outcome != Outcome::Uncertain => {
                state.phase = Phase::Idle;
                Ok(())
            }
            _ => Err(AdmissionError::ReconciliationRequired),
        }
    }

    pub async fn wait_terminal(&self) {
        loop {
            let notified = self.0.terminal.notified();
            // Register before inspecting state to avoid missing the transition.
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !matches!(self.0.state.lock().unwrap().phase, Phase::Running { .. }) {
                return;
            }
            notified.await;
        }
    }

    pub async fn shutdown(&self) {
        {
            let mut state = self.0.state.lock().unwrap();
            state.shutdown = true;
            if let Phase::Running { cancel, .. } = &state.phase {
                cancel.request();
            }
        }
        let worker = self.0.worker.lock().unwrap().take();
        if let Some(worker) = worker {
            let _ = worker.await;
        }
    }
}
