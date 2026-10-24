//! Process-local ownership across cancellation of a requesting future.
//! One admitted operation and one retained completion; no admission queue.

use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, Notify};

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
}

enum Phase {
    RecoveryRequired,
    Idle,
    Running {
        id: u64,
        cancel: Cancellation,
        managed: bool,
    },
    Retained {
        id: u64,
        result: Completion,
    },
}

struct State {
    phase: Phase,
    next_id: u64,
    shutdown: bool,
}

struct Shared {
    state: Mutex<State>,
    terminal: Notify,
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
    // Admission below fences every native writer. Higher-level transactions
    // keep their existing address_work lock; reacquiring it here would deadlock.
    pub fn for_serialized_writers() -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State {
                phase: Phase::RecoveryRequired,
                next_id: 0,
                shutdown: false,
            }),
            terminal: Notify::new(),
            worker: Mutex::new(None),
        }))
    }

    pub fn submit<F, Fut>(&self, work: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(false, false, work)
    }

    pub fn submit_managed<F, Fut>(&self, work: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(false, true, work)
    }

    pub fn reconcile<F, Fut>(&self, observe: F) -> Result<Pending, AdmissionError>
    where
        F: FnOnce(Cancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Completion> + Send + 'static,
    {
        self.start(true, true, observe)
    }

    fn start<F, Fut>(
        &self,
        recovery: bool,
        managed: bool,
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
        match (&state.phase, recovery) {
            (Phase::Running { .. }, _) => return Err(AdmissionError::Busy),
            (Phase::Idle, _) | (_, true) => (),
            _ => return Err(AdmissionError::ReconciliationRequired),
        }
        state.next_id = state.next_id.checked_add(1).expect("operation counter");
        let id = state.next_id;
        let cancel = Cancellation::default();
        state.phase = Phase::Running {
            id,
            cancel: cancel.clone(),
            managed,
        };
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
        Ok(Pending {
            id,
            response,
            cancel,
        })
    }

    fn finish(shared: Arc<Shared>, id: u64, recovery: bool, result: Completion) {
        let mut state = shared.state.lock().unwrap();
        assert!(matches!(state.phase, Phase::Running { id: running, .. } if running == id));
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

    pub fn available(&self) -> Result<(), AdmissionError> {
        let state = self.0.state.lock().unwrap();
        if state.shutdown {
            return Err(AdmissionError::ShuttingDown);
        }
        match state.phase {
            Phase::Idle => Ok(()),
            Phase::Running { .. } => Err(AdmissionError::Busy),
            _ => Err(AdmissionError::ReconciliationRequired),
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn recovery_drain_does_not_wait_for_a_manager_lock_held_by_its_caller() {
        let executor = LocalExecutor::for_serialized_writers();
        let (release, wait) = oneshot::channel();
        let ticket = executor
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
