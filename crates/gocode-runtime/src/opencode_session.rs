//! Runtime ownership and cancellation for OpenCode-compatible session prompts.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use gocode_opencode_compat::{
    CanonicalPrompt, CanonicalPromptResult, CanonicalSessionStatus, SessionV1HostError,
    SessionV1HostPort,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Boxed runtime execution future.
pub type PromptExecutionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CanonicalPromptResult, SessionV1HostError>> + Send + 'a>>;

/// Phase 7-backed prompt execution boundary.
///
/// Implementations own durable TaskRun/provider/tool/event execution. This
/// host adds only session-level mutual exclusion, status and cancellation.
pub trait PromptExecutionPort: Clone + Send + Sync + 'static {
    /// Executes one canonical prompt under a runtime-owned cancellation token.
    fn execute(
        &self,
        prompt: CanonicalPrompt,
        cancellation: CancellationToken,
    ) -> PromptExecutionFuture<'_>;
}

struct ActiveExecution {
    generation: u64,
    cancellation: CancellationToken,
    completed: Arc<Notify>,
}

struct SharedState {
    active: Mutex<BTreeMap<String, ActiveExecution>>,
    next_generation: AtomicU64,
}

struct ExecutionGuard {
    state: Arc<SharedState>,
    session_id: String,
    generation: u64,
}

impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.state.active.lock()
            && active
                .get(&self.session_id)
                .is_some_and(|entry| entry.generation == self.generation)
            && let Some(execution) = active.remove(&self.session_id)
        {
            execution.completed.notify_waiters();
        }
    }
}

/// Production session lifecycle adapter for the compatibility service.
#[derive(Clone)]
pub struct RuntimeSessionV1Host<E> {
    executor: E,
    state: Arc<SharedState>,
    abort_timeout: Duration,
}

impl<E: PromptExecutionPort> RuntimeSessionV1Host<E> {
    /// Constructs an empty runtime host. After restart no transient execution
    /// is reported as active, matching the pinned OpenCode status semantics.
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            state: Arc::new(SharedState {
                active: Mutex::new(BTreeMap::new()),
                next_generation: AtomicU64::new(1),
            }),
            abort_timeout: Duration::from_secs(30),
        }
    }

    /// Overrides the bounded wait for downstream cancellation acknowledgement.
    pub fn with_abort_timeout(
        mut self,
        abort_timeout: Duration,
    ) -> Result<Self, SessionV1HostError> {
        if abort_timeout.is_zero() {
            return Err(SessionV1HostError::Timeout);
        }
        self.abort_timeout = abort_timeout;
        Ok(self)
    }

    fn acquire(
        &self,
        session_id: &str,
    ) -> Result<(ExecutionGuard, CancellationToken), SessionV1HostError> {
        let mut active = self
            .state
            .active
            .lock()
            .map_err(|_| SessionV1HostError::StorageFailure)?;
        if active.contains_key(session_id) {
            return Err(SessionV1HostError::Conflict);
        }
        let generation = self
            .state
            .next_generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| SessionV1HostError::StorageFailure)?;
        let cancellation = CancellationToken::new();
        let completed = Arc::new(Notify::new());
        active.insert(
            session_id.to_owned(),
            ActiveExecution {
                generation,
                cancellation: cancellation.clone(),
                completed,
            },
        );
        Ok((
            ExecutionGuard {
                state: Arc::clone(&self.state),
                session_id: session_id.to_owned(),
                generation,
            },
            cancellation,
        ))
    }
}

impl<E: PromptExecutionPort> SessionV1HostPort for RuntimeSessionV1Host<E> {
    async fn prompt(
        &self,
        input: CanonicalPrompt,
    ) -> Result<CanonicalPromptResult, SessionV1HostError> {
        let session_id = input.session_id.clone();
        let (_guard, cancellation) = self.acquire(&session_id)?;
        self.executor.execute(input, cancellation).await
    }

    async fn prompt_async(&self, input: CanonicalPrompt) -> Result<(), SessionV1HostError> {
        let session_id = input.session_id.clone();
        let (guard, cancellation) = self.acquire(&session_id)?;
        let executor = self.executor.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let _ = executor.execute(input, cancellation).await;
        });
        Ok(())
    }

    async fn status(&self) -> Result<Vec<(String, CanonicalSessionStatus)>, SessionV1HostError> {
        let active = self
            .state
            .active
            .lock()
            .map_err(|_| SessionV1HostError::StorageFailure)?;
        Ok(active
            .keys()
            .cloned()
            .map(|session_id| (session_id, CanonicalSessionStatus::Busy))
            .collect())
    }

    async fn abort(&self, session_id: String) -> Result<bool, SessionV1HostError> {
        let (generation, cancellation, completed) = {
            let active = self
                .state
                .active
                .lock()
                .map_err(|_| SessionV1HostError::StorageFailure)?;
            let Some(execution) = active.get(&session_id) else {
                return Ok(false);
            };
            (
                execution.generation,
                execution.cancellation.clone(),
                Arc::clone(&execution.completed),
            )
        };
        cancellation.cancel();
        let wait = async {
            loop {
                let notified = completed.notified();
                let still_active = self
                    .state
                    .active
                    .lock()
                    .map_err(|_| SessionV1HostError::StorageFailure)?
                    .get(&session_id)
                    .is_some_and(|execution| execution.generation == generation);
                if !still_active {
                    break;
                }
                notified.await;
            }
            Ok::<(), SessionV1HostError>(())
        };
        tokio::time::timeout(self.abort_timeout, wait)
            .await
            .map_err(|_| SessionV1HostError::Timeout)??;
        let no_replacement = !self
            .state
            .active
            .lock()
            .map_err(|_| SessionV1HostError::StorageFailure)?
            .contains_key(&session_id);
        if !no_replacement {
            // A newer generation cannot be reported as cancelled by this call.
            return Err(SessionV1HostError::Conflict);
        }
        Ok(true)
    }
}
