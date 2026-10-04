use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_application::ports::{EventStoreError, TaskRunQueueCandidate, TaskRunQueueScanPage};
use runne_domain::id::TaskRunId;
use runne_provider::ProviderFuture;
use runne_runtime::{AutomaticTaskRunError, AutomaticTaskRunService};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

struct HeldCancellationService {
    queue_returned: AtomicBool,
    executions: AtomicUsize,
    executed_taskrun_id: Mutex<Option<TaskRunId>>,
    cancellation_starts: AtomicUsize,
    active_cancellations: AtomicUsize,
    release_cancellation: Notify,
}

fn candidate(byte: u8) -> TaskRunQueueCandidate {
    TaskRunQueueCandidate {
        taskrun_id: TaskRunId::from_bytes([byte; 16]),
        current_version: 3,
    }
}

impl AutomaticTaskRunService for HeldCancellationService {
    fn scan_queued(
        &self,
        _after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        assert_eq!(limit, 128);
        let candidates = if self.queue_returned.swap(true, Ordering::SeqCst) {
            Vec::new()
        } else {
            vec![candidate(72), candidate(71)]
        };
        Ok(TaskRunQueueScanPage {
            next_cursor: None,
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
        assert_eq!(limit, 128);
        let candidates = vec![candidate(72), candidate(73)];
        Ok(TaskRunQueueScanPage {
            next_cursor: Some(candidate(73).taskrun_id),
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
            self.executions.fetch_add(1, Ordering::SeqCst);
            *self.executed_taskrun_id.lock().unwrap() = Some(candidate.taskrun_id);
            Ok(())
        })
    }

    fn complete_queued_cancellation(
        &self,
        _taskrun_id: TaskRunId,
        _expected_version: u64,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async move {
            self.cancellation_starts.fetch_add(1, Ordering::SeqCst);
            self.active_cancellations.fetch_add(1, Ordering::SeqCst);
            self.release_cancellation.notified().await;
            self.active_cancellations.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

#[tokio::test]
async fn one_held_cancellation_can_overlap_execution_and_drains_on_shutdown() {
    let service = Arc::new(HeldCancellationService {
        queue_returned: AtomicBool::new(false),
        executions: AtomicUsize::new(0),
        executed_taskrun_id: Mutex::new(None),
        cancellation_starts: AtomicUsize::new(0),
        active_cancellations: AtomicUsize::new(0),
        release_cancellation: Notify::new(),
    });
    let stop = CancellationToken::new();
    let worker = tokio::spawn(
        runne_runtime::taskrun_auto_worker::run_automatic_taskrun_worker(
            service.clone(),
            stop.clone(),
        ),
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if service.executions.load(Ordering::SeqCst) == 1
                && service.active_cancellations.load(Ordering::SeqCst) == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("execution and one pending cancellation should both start");
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(service.cancellation_starts.load(Ordering::SeqCst), 1);
    assert_eq!(service.active_cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(
        *service.executed_taskrun_id.lock().unwrap(),
        Some(candidate(71).taskrun_id),
        "the pending cancellation's task must be skipped in queue results"
    );

    stop.cancel();
    assert!(
        !worker.is_finished(),
        "shutdown must drain the held settlement"
    );
    service.release_cancellation.notify_one();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker drains cancellation settlement")
        .expect("worker task completes");
    assert_eq!(service.cancellation_starts.load(Ordering::SeqCst), 1);
}
