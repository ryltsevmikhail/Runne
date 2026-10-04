use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_application::ports::{EventStoreError, TaskRunQueueCandidate, TaskRunQueueScanPage};
use runne_domain::id::TaskRunId;
use runne_provider::ProviderFuture;
use runne_runtime::{AutomaticTaskRunError, AutomaticTaskRunService};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

struct PagedService {
    ids: Vec<TaskRunId>,
    queued: Vec<TaskRunQueueCandidate>,
    cancellations: Vec<TaskRunQueueCandidate>,
    queue_attempts: Mutex<Vec<TaskRunId>>,
    cancellation_attempts: Mutex<Vec<(TaskRunId, Instant)>>,
    completed_cancellations: Mutex<Vec<TaskRunId>>,
    blocked_queue: TaskRunId,
    blocked_cancellation: TaskRunId,
}

impl AutomaticTaskRunService for PagedService {
    fn scan_queued(
        &self,
        after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        Ok(scan_page(&self.ids, &self.queued, after, limit))
    }

    fn scan_pending_cancellations(
        &self,
        after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        let completed = self.completed_cancellations.lock().unwrap();
        let pending: Vec<_> = self
            .cancellations
            .iter()
            .copied()
            .filter(|candidate| !completed.contains(&candidate.taskrun_id))
            .collect();
        Ok(scan_page(&self.ids, &pending, after, limit))
    }

    fn execute_queued(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async move {
            self.queue_attempts
                .lock()
                .unwrap()
                .push(candidate.taskrun_id);
            if candidate.taskrun_id == self.blocked_queue {
                Err(AutomaticTaskRunError::Unavailable)
            } else {
                Ok(())
            }
        })
    }

    fn complete_queued_cancellation(
        &self,
        taskrun_id: TaskRunId,
        _expected_version: u64,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async move {
            self.cancellation_attempts
                .lock()
                .unwrap()
                .push((taskrun_id, Instant::now()));
            if taskrun_id == self.blocked_cancellation {
                Err(AutomaticTaskRunError::Uncertain)
            } else {
                self.completed_cancellations
                    .lock()
                    .unwrap()
                    .push(taskrun_id);
                Ok(())
            }
        })
    }
}

fn scan_page(
    ids: &[TaskRunId],
    candidates: &[TaskRunQueueCandidate],
    after: Option<TaskRunId>,
    limit: usize,
) -> TaskRunQueueScanPage {
    let mut examined: Vec<_> = ids
        .iter()
        .copied()
        .filter(|id| after.is_none_or(|cursor| *id > cursor))
        .take(limit + 1)
        .collect();
    let reached_end = examined.len() <= limit;
    examined.truncate(limit);
    let next_cursor = examined.last().copied().or(after);
    let scanned = examined;
    let candidates = candidates
        .iter()
        .copied()
        .filter(|candidate| scanned.contains(&candidate.taskrun_id))
        .collect();
    TaskRunQueueScanPage {
        candidates,
        next_cursor,
        reached_end,
        examined: scanned.len(),
    }
}

fn id(value: u128) -> TaskRunId {
    TaskRunId::from_bytes(value.to_be_bytes())
}

fn candidate(value: u128, current_version: u64) -> TaskRunQueueCandidate {
    TaskRunQueueCandidate {
        taskrun_id: id(value),
        current_version,
    }
}

fn service(
    count: u128,
    queued: Vec<TaskRunQueueCandidate>,
    cancellations: Vec<TaskRunQueueCandidate>,
    blocked_queue: TaskRunId,
    blocked_cancellation: TaskRunId,
) -> Arc<PagedService> {
    Arc::new(PagedService {
        ids: (1..=count).map(id).collect(),
        queued,
        cancellations,
        queue_attempts: Mutex::new(Vec::new()),
        cancellation_attempts: Mutex::new(Vec::new()),
        completed_cancellations: Mutex::new(Vec::new()),
        blocked_queue,
        blocked_cancellation,
    })
}

async fn advance_worker(stop: &CancellationToken, worker: tokio::task::JoinHandle<()>) {
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker drains active work")
        .expect("worker task completes");
}

#[tokio::test(start_paused = true)]
async fn blocked_first_candidate_does_not_starve_later_candidate_across_pages() {
    let blocked = candidate(1, 2);
    let eligible = candidate(2, 2);
    let service = service(
        129,
        vec![blocked, eligible],
        vec![],
        blocked.taskrun_id,
        id(999),
    );
    let stop = CancellationToken::new();
    let worker = tokio::spawn(
        runne_runtime::taskrun_auto_worker::run_automatic_taskrun_worker(
            service.clone(),
            stop.clone(),
        ),
    );

    for _ in 0..6 {
        tokio::task::yield_now().await;
        if service
            .queue_attempts
            .lock()
            .unwrap()
            .contains(&eligible.taskrun_id)
        {
            break;
        }
        tokio::time::advance(Duration::from_millis(100)).await;
    }
    let attempts = service.queue_attempts.lock().unwrap().clone();
    advance_worker(&stop, worker).await;
    assert!(
        attempts.contains(&eligible.taskrun_id),
        "later candidate starved: {attempts:?}"
    );
    assert_eq!(attempts.first(), Some(&blocked.taskrun_id));
}

#[tokio::test(start_paused = true)]
async fn failed_cancellation_does_not_starve_later_candidate_after_cooldown_sweep() {
    let blocked = candidate(1, 5);
    let eligible = candidate(2, 5);
    let service = service(
        1409,
        vec![],
        vec![blocked, eligible],
        id(999),
        blocked.taskrun_id,
    );
    let stop = CancellationToken::new();
    let started = Instant::now();
    let worker = tokio::spawn(
        runne_runtime::taskrun_auto_worker::run_automatic_taskrun_worker(
            service.clone(),
            stop.clone(),
        ),
    );

    for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
    }
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    let attempts = service.cancellation_attempts.lock().unwrap().clone();
    let completed = service.completed_cancellations.lock().unwrap().clone();
    advance_worker(&stop, worker).await;
    let blocked_attempts: Vec<_> = attempts
        .iter()
        .filter(|(taskrun_id, _)| *taskrun_id == blocked.taskrun_id)
        .map(|(_, at)| *at)
        .collect();
    assert!(
        completed.contains(&eligible.taskrun_id),
        "later cancellation starved: {attempts:?}"
    );
    assert_eq!(
        completed
            .iter()
            .filter(|taskrun_id| **taskrun_id == eligible.taskrun_id)
            .count(),
        1,
        "the fake service records one successful settlement acknowledgement"
    );
    assert!(
        blocked_attempts.len() >= 2,
        "cooldown retry did not occur: {attempts:?}"
    );
    assert!(
        blocked_attempts
            .windows(2)
            .all(|pair| { pair[1].duration_since(pair[0]) >= Duration::from_secs(1) }),
        "blocked retries bypassed the cooldown: {attempts:?}"
    );
    assert!(Instant::now().duration_since(started) > Duration::from_secs(1));
}
