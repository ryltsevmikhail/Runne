use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_application::ports::{EventStoreError, TaskRunQueueCandidate, TaskRunQueueScanPage};
use runne_domain::id::TaskRunId;
use runne_provider::ProviderFuture;
use runne_runtime::{AutomaticTaskRunError, AutomaticTaskRunService};
use tokio_util::sync::CancellationToken;

#[path = "taskrun_auto_worker/pagination.rs"]
mod pagination;
#[path = "taskrun_auto_worker/remote_observer.rs"]
mod remote_observer;

struct QueueService {
    candidates: Vec<TaskRunQueueCandidate>,
    executions: Mutex<Vec<TaskRunId>>,
    cancellations: Vec<TaskRunQueueCandidate>,
    completed_cancellations: Mutex<Vec<TaskRunId>>,
    panic_on: Option<TaskRunId>,
}

impl AutomaticTaskRunService for QueueService {
    fn scan_queued(
        &self,
        _after: Option<TaskRunId>,
        _limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        Ok(TaskRunQueueScanPage {
            candidates: self.candidates.clone(),
            next_cursor: self.candidates.last().map(|candidate| candidate.taskrun_id),
            reached_end: true,
            examined: self.candidates.len(),
        })
    }

    fn scan_pending_cancellations(
        &self,
        _after: Option<TaskRunId>,
        _limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        let completed = self.completed_cancellations.lock().unwrap();
        let candidates: Vec<_> = self
            .cancellations
            .iter()
            .copied()
            .filter(|candidate| !completed.contains(&candidate.taskrun_id))
            .collect();
        Ok(TaskRunQueueScanPage {
            next_cursor: candidates.last().map(|candidate| candidate.taskrun_id),
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
            self.executions.lock().unwrap().push(candidate.taskrun_id);
            if self.panic_on == Some(candidate.taskrun_id) {
                panic!("simulated worker panic after claim");
            }
            Ok(())
        })
    }

    fn complete_queued_cancellation(
        &self,
        taskrun_id: TaskRunId,
        _expected_version: u64,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async move {
            self.completed_cancellations
                .lock()
                .unwrap()
                .push(taskrun_id);
            Ok(())
        })
    }
}

fn candidate(byte: u8) -> TaskRunQueueCandidate {
    TaskRunQueueCandidate {
        taskrun_id: TaskRunId::from_bytes([byte; 16]),
        current_version: 2,
    }
}

#[tokio::test]
async fn worker_skips_panicked_claim_and_continues_to_next_queued_run() {
    let first = candidate(31);
    let second = candidate(32);
    let service = Arc::new(QueueService {
        candidates: vec![first, second],
        executions: Mutex::new(Vec::new()),
        cancellations: vec![],
        completed_cancellations: Mutex::new(Vec::new()),
        panic_on: Some(first.taskrun_id),
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
            if service
                .executions
                .lock()
                .unwrap()
                .contains(&second.taskrun_id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("later queued run should not be starved by the panicked claim");
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker drains before shutdown")
        .expect("worker task completes");
}

#[tokio::test]
async fn worker_drains_an_active_execution_before_stopping() {
    struct SlowService(tokio::sync::Notify);
    impl AutomaticTaskRunService for SlowService {
        fn scan_queued(
            &self,
            _after: Option<TaskRunId>,
            _limit: usize,
        ) -> Result<TaskRunQueueScanPage, EventStoreError> {
            Ok(TaskRunQueueScanPage {
                candidates: vec![candidate(41)],
                next_cursor: None,
                reached_end: true,
                examined: 1,
            })
        }
        fn execute_queued(
            &self,
            _candidate: TaskRunQueueCandidate,
        ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
            Box::pin(async move {
                self.0.notified().await;
                Ok(())
            })
        }
    }
    let service = Arc::new(SlowService(tokio::sync::Notify::new()));
    let stop = CancellationToken::new();
    let worker = tokio::spawn(
        runne_runtime::taskrun_auto_worker::run_automatic_taskrun_worker(
            service.clone(),
            stop.clone(),
        ),
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    stop.cancel();
    assert!(
        !worker.is_finished(),
        "active provider future remains owned"
    );
    service.0.notify_waiters();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker drains active execution")
        .expect("worker task completes");
}

#[tokio::test]
async fn startup_scan_completes_committed_queued_cancellation() {
    let cancellation = candidate(51);
    let service = Arc::new(QueueService {
        candidates: vec![],
        executions: Mutex::new(Vec::new()),
        cancellations: vec![cancellation],
        completed_cancellations: Mutex::new(Vec::new()),
        panic_on: None,
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
            if service
                .completed_cancellations
                .lock()
                .unwrap()
                .contains(&cancellation.taskrun_id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("committed cancellation is recovered after restart");
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap();
}
