use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_application::ports::{EventStoreError, TaskRunQueueCandidate, TaskRunQueueScanPage};
use runne_domain::id::TaskRunId;
use runne_provider::ProviderFuture;
use runne_runtime::{AutomaticTaskRunError, AutomaticTaskRunService};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

struct ActiveExecutionService {
    executions: AtomicUsize,
    execution_ids: Mutex<Vec<TaskRunId>>,
    active_executions: AtomicUsize,
    first_execution_finished: AtomicBool,
    cancellations: AtomicUsize,
    completed_cancellations: AtomicUsize,
    release_execution: Notify,
    cancellation_succeeds: bool,
}

impl AutomaticTaskRunService for ActiveExecutionService {
    fn scan_queued(
        &self,
        _after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        assert_eq!(limit, 128, "queue scan remains bounded");
        let candidates = if !self.first_execution_finished.load(Ordering::SeqCst) {
            vec![candidate(61), candidate(62)]
        } else {
            vec![candidate(62)]
        };
        Ok(TaskRunQueueScanPage {
            next_cursor: Some(candidate(62).taskrun_id),
            reached_end: true,
            examined: candidates.len(),
            candidates,
        })
    }

    fn scan_pending_cancellations(
        &self,
        _after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        assert_eq!(limit, 128, "cancellation scan remains bounded");
        let candidates = if self.active_executions.load(Ordering::SeqCst) == 1
            && self.completed_cancellations.load(Ordering::SeqCst) == 0
        {
            vec![candidate(63)]
        } else {
            Vec::new()
        };
        Ok(TaskRunQueueScanPage {
            next_cursor: candidates.last().map(|item| item.taskrun_id),
            reached_end: true,
            examined: candidates.len(),
            candidates,
        })
    }

    fn execute_queued(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async move {
            let execution = self.executions.fetch_add(1, Ordering::SeqCst);
            self.execution_ids
                .lock()
                .unwrap()
                .push(candidate.taskrun_id);
            if execution == 0 {
                self.active_executions.fetch_add(1, Ordering::SeqCst);
                self.release_execution.notified().await;
                self.active_executions.fetch_sub(1, Ordering::SeqCst);
                self.first_execution_finished.store(true, Ordering::SeqCst);
            }
            Ok(())
        })
    }

    fn complete_queued_cancellation(
        &self,
        _taskrun_id: TaskRunId,
        _expected_version: u64,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async move {
            self.cancellations.fetch_add(1, Ordering::SeqCst);
            if self.cancellation_succeeds {
                self.completed_cancellations.fetch_add(1, Ordering::SeqCst);
                Ok(())
            } else {
                Err(AutomaticTaskRunError::Uncertain)
            }
        })
    }
}

fn candidate(byte: u8) -> TaskRunQueueCandidate {
    TaskRunQueueCandidate {
        taskrun_id: TaskRunId::from_bytes([byte; 16]),
        current_version: 2,
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker should make progress while provider execution is held");
}

async fn stop_after_releasing(
    service: &ActiveExecutionService,
    stop: &CancellationToken,
    worker: tokio::task::JoinHandle<()>,
) {
    stop.cancel();
    service.release_execution.notify_one();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker drains its active provider future")
        .expect("worker task completes");
}

#[tokio::test]
async fn queued_cancellation_settles_while_one_provider_execution_remains_blocked() {
    let service = Arc::new(ActiveExecutionService {
        executions: AtomicUsize::new(0),
        execution_ids: Mutex::new(Vec::new()),
        active_executions: AtomicUsize::new(0),
        first_execution_finished: AtomicBool::new(false),
        cancellations: AtomicUsize::new(0),
        completed_cancellations: AtomicUsize::new(0),
        release_execution: Notify::new(),
        cancellation_succeeds: true,
    });
    let stop = CancellationToken::new();
    let worker = tokio::spawn(
        runne_runtime::taskrun_auto_worker::run_automatic_taskrun_worker(
            service.clone(),
            stop.clone(),
        ),
    );

    wait_until(|| service.active_executions.load(Ordering::SeqCst) == 1).await;
    wait_until(|| service.completed_cancellations.load(Ordering::SeqCst) == 1).await;
    assert_eq!(service.active_executions.load(Ordering::SeqCst), 1);
    assert_eq!(service.executions.load(Ordering::SeqCst), 1);
    assert_eq!(
        service.execution_ids.lock().unwrap().as_slice(),
        &[candidate(61).taskrun_id]
    );
    assert_eq!(service.cancellations.load(Ordering::SeqCst), 1);

    stop_after_releasing(service.as_ref(), &stop, worker).await;
}

#[tokio::test]
async fn uncertain_cancellation_retries_without_dropping_or_restarting_execution() {
    let service = Arc::new(ActiveExecutionService {
        executions: AtomicUsize::new(0),
        execution_ids: Mutex::new(Vec::new()),
        active_executions: AtomicUsize::new(0),
        first_execution_finished: AtomicBool::new(false),
        cancellations: AtomicUsize::new(0),
        completed_cancellations: AtomicUsize::new(0),
        release_execution: Notify::new(),
        cancellation_succeeds: false,
    });
    let stop = CancellationToken::new();
    let worker = tokio::spawn(
        runne_runtime::taskrun_auto_worker::run_automatic_taskrun_worker(
            service.clone(),
            stop.clone(),
        ),
    );

    wait_until(|| service.active_executions.load(Ordering::SeqCst) == 1).await;
    wait_until(|| service.cancellations.load(Ordering::SeqCst) == 1).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(service.cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(service.active_executions.load(Ordering::SeqCst), 1);
    assert_eq!(service.executions.load(Ordering::SeqCst), 1);
    assert_eq!(
        service.execution_ids.lock().unwrap().as_slice(),
        &[candidate(61).taskrun_id]
    );
    assert_eq!(service.completed_cancellations.load(Ordering::SeqCst), 0);

    wait_until(|| service.cancellations.load(Ordering::SeqCst) >= 2).await;
    assert_eq!(service.active_executions.load(Ordering::SeqCst), 1);
    assert_eq!(service.executions.load(Ordering::SeqCst), 1);
    service.release_execution.notify_one();
    wait_until(|| service.executions.load(Ordering::SeqCst) == 2).await;
    assert_eq!(
        service.execution_ids.lock().unwrap().as_slice(),
        &[candidate(61).taskrun_id, candidate(62).taskrun_id]
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker drains before shutdown")
        .expect("worker task completes");
}
