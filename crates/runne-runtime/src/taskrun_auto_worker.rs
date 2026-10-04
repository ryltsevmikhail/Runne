//! Runtime-owned polling and supervision for durably queued TaskRuns.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use runne_application::ports::{EventStoreError, TaskRunQueueCandidate, TaskRunQueueScanPage};
use runne_domain::id::TaskRunId;
use runne_provider::DispatchAttemptId;
use runne_provider::ProviderFuture;
use tokio::task::{Id as JoinId, JoinSet};
use tokio_util::sync::CancellationToken;
#[path = "taskrun_auto_worker/logging.rs"]
mod logging;
#[path = "taskrun_auto_worker/saved_remote_observer.rs"]
mod saved_remote_observer;
use logging::{
    warn_execution, warn_scan_failure, warn_shutdown_execution, warn_shutdown_panic,
    warn_worker_panic,
};

/// Runtime-to-daemon boundary for scanning and executing admitted TaskRuns.
pub trait AutomaticTaskRunService: Send + Sync + 'static {
    /// Reads one bounded page of authoritative queued TaskRuns.
    fn scan_queued(
        &self,
        after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError>;

    /// Reads pending cancellation requests, including requests interrupted
    /// after commit but before terminalization.
    fn scan_pending_cancellations(
        &self,
        after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        let _ = (after, limit);
        Ok(TaskRunQueueScanPage {
            candidates: Vec::new(),
            next_cursor: None,
            reached_end: true,
            examined: 0,
        })
    }

    /// Executes one exact queued candidate through the admitted provider path.
    fn execute_queued(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>>;

    /// Attempts cancellation settlement only when the authoritative store can
    /// prove either no claim occurred or the exact claim never began text
    /// generation and produced no provider effect. These are distinct atomic
    /// store paths; started or unknown effects remain pending.
    fn complete_queued_cancellation(
        &self,
        taskrun_id: TaskRunId,
        expected_version: u64,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        let _ = (taskrun_id, expected_version);
        Box::pin(async { Err(AutomaticTaskRunError::Unavailable) })
    }

    /// Observes one bounded page of previously saved remote response identities.
    /// Implementations must not dispatch or claim work from this recovery path.
    fn observe_saved_remote_page(
        &self,
        after: Option<DispatchAttemptId>,
        limit: usize,
    ) -> ProviderFuture<'_, Result<SavedRemoteObservationProgress, AutomaticTaskRunError>> {
        let _ = (after, limit);
        Box::pin(async {
            Ok(SavedRemoteObservationProgress {
                next_after: None,
                reached_end: true,
                unavailable_candidates: 0,
            })
        })
    }
}

/// Keyset progress for the bounded saved-remote observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SavedRemoteObservationProgress {
    /// Resume after this exact provider attempt on the next tick.
    pub next_after: Option<DispatchAttemptId>,
    /// The current sweep has reached the end and should restart at its next tick.
    pub reached_end: bool,
    /// Number of candidates that could not be authenticated or observed in this page.
    pub unavailable_candidates: usize,
}

/// Closed execution outcomes reported to runtime diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomaticTaskRunError {
    /// Execution was rejected before any provider effect.
    RejectedBeforeEffect,
    /// A provider or durable application reported a known failure.
    Failed,
    /// The provider effect or terminal state cannot be established.
    Uncertain,
    /// Runtime-owned execution infrastructure is unavailable.
    Unavailable,
}

/// Polls a bounded durable queue, owns one execution future per TaskRun, and
/// stops admitting work before draining active jobs during runtime shutdown.
pub async fn run_automatic_taskrun_worker(
    service: Arc<dyn AutomaticTaskRunService>,
    stop_scanning: CancellationToken,
) {
    const PAGE_SIZE: usize = 128;
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    let mut cursor = None;
    let mut cancellation_cursor = None;
    let mut active = HashMap::<JoinId, (TaskRunId, bool)>::new();
    let mut deferred_queued = HashSet::new();
    let mut deferred_cancellations = HashSet::new();
    let mut cancellation_retry_not_before = tokio::time::Instant::now();
    let mut jobs = JoinSet::new();
    let observer_stop = stop_scanning.child_token();
    let observer_service = Arc::clone(&service);
    let observer = tokio::spawn(saved_remote_observer::run(observer_service, observer_stop));
    loop {
        tokio::select! {
            biased;
            _ = stop_scanning.cancelled() => break,
            joined = jobs.join_next_with_id(), if !jobs.is_empty() => {
                match joined {
                    Some(Ok((join_id, (taskrun_id, result)))) => {
                        let cancellation = active.remove(&join_id).is_some_and(|(_, value)| value);
                        if let Err(error) = result {
                            if cancellation {
                                deferred_cancellations.insert(taskrun_id);
                                cancellation_retry_not_before =
                                    tokio::time::Instant::now() + Duration::from_secs(1);
                            } else {
                                deferred_queued.insert(taskrun_id);
                            }
                            warn_execution(taskrun_id, error);
                        }
                    }
                    Some(Err(error)) => {
                        if let Some((taskrun_id, cancellation)) = active.remove(&error.id()) {
                            if cancellation {
                                deferred_cancellations.insert(taskrun_id);
                                cancellation_retry_not_before =
                                    tokio::time::Instant::now() + Duration::from_secs(1);
                            } else {
                                deferred_queued.insert(taskrun_id);
                            }
                            warn_worker_panic(taskrun_id);
                        }
                    }
                    None => {}
                }
            }
            _ = interval.tick() => {
                let cancellation_active = active.values().any(|(_, cancellation)| *cancellation);
                if !cancellation_active {
                    let cancellations = match service.scan_pending_cancellations(cancellation_cursor, PAGE_SIZE) {
                        Ok(page) => page,
                        Err(error) => {
                            warn_scan_failure(error, true);
                            continue;
                        }
                    };
                    let cancellation_end = cancellations.reached_end;
                    if let Some(candidate) = cancellations.candidates
                        .into_iter()
                        .find(|candidate| !deferred_cancellations.contains(&candidate.taskrun_id))
                    {
                        let taskrun_id = candidate.taskrun_id;
                        // Keep the keyset cursor at the selected candidate. A
                        // page can contain more candidates than we launch in
                        // this tick; advancing to its last examined stream
                        // would lose those candidates until the next sweep.
                        cancellation_cursor = Some(taskrun_id);
                        let executor = Arc::clone(&service);
                        let join_id = jobs.spawn(async move {
                            let result = executor
                                .complete_queued_cancellation(taskrun_id, candidate.current_version)
                                .await;
                            (taskrun_id, result)
                        }).id();
                        active.insert(join_id, (taskrun_id, true));
                    } else if cancellation_end
                    {
                        cancellation_cursor = None;
                        if tokio::time::Instant::now() >= cancellation_retry_not_before {
                            deferred_cancellations.clear();
                        }
                    } else {
                        cancellation_cursor = cancellations.next_cursor;
                    }
                }

                let execution_active = active.values().any(|(_, cancellation)| !*cancellation);
                if !execution_active {
                    let page = match service.scan_queued(cursor, PAGE_SIZE) {
                        Ok(page) => page,
                        Err(error) => {
                            warn_scan_failure(error, false);
                            continue;
                        }
                    };
                    let page_next_cursor = page.next_cursor;
                    let candidates = page.candidates;
                    let reached_end = page.reached_end;
                    if let Some(candidate) = candidates
                        .into_iter()
                        .find(|candidate| {
                            !deferred_queued.contains(&candidate.taskrun_id)
                                && !active.values().any(|(taskrun_id, cancellation)| {
                                    *cancellation && *taskrun_id == candidate.taskrun_id
                                })
                        })
                    {
                        let taskrun_id = candidate.taskrun_id;
                        // Retain candidates later in the examined page by
                        // resuming just after the one admitted for execution.
                        cursor = Some(taskrun_id);
                        let executor = Arc::clone(&service);
                        let join_id = jobs.spawn(async move {
                            let result = executor.execute_queued(candidate).await;
                            (taskrun_id, result)
                        }).id();
                        active.insert(join_id, (taskrun_id, false));
                    } else if reached_end {
                        cursor = None;
                        deferred_queued.clear();
                    } else {
                        cursor = page_next_cursor;
                    }
                }
            }
        }
    }
    while let Some(joined) = jobs.join_next_with_id().await {
        match joined {
            Ok((join_id, (taskrun_id, Err(error)))) => {
                active.remove(&join_id);
                warn_shutdown_execution(taskrun_id, error);
            }
            Ok((join_id, (_taskrun_id, Ok(())))) => {
                active.remove(&join_id);
            }
            Err(error) => {
                if let Some((taskrun_id, _)) = active.remove(&error.id()) {
                    warn_shutdown_panic(taskrun_id);
                }
            }
        }
    }
    let _ = observer.await;
}
