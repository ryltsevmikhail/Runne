use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_application::ports::{EventStoreError, TaskRunQueueCandidate, TaskRunQueueScanPage};
use runne_domain::id::TaskRunId;
use runne_provider::{DispatchAttemptId, ProviderFuture};
use runne_runtime::taskrun_auto_worker::{
    AutomaticTaskRunError, AutomaticTaskRunService, SavedRemoteObservationProgress,
    run_automatic_taskrun_worker,
};
use tokio_util::sync::CancellationToken;

struct Observer {
    cursors: Mutex<Vec<Option<DispatchAttemptId>>>,
    pages: Mutex<Vec<SavedRemoteObservationProgress>>,
    hold: bool,
}

impl AutomaticTaskRunService for Observer {
    fn scan_queued(
        &self,
        _after: Option<TaskRunId>,
        _limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        Ok(TaskRunQueueScanPage {
            candidates: Vec::new(),
            next_cursor: None,
            reached_end: true,
            examined: 0,
        })
    }

    fn execute_queued(
        &self,
        _candidate: TaskRunQueueCandidate,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        panic!("saved-remote observation must never dispatch queued work")
    }

    fn observe_saved_remote_page(
        &self,
        after: Option<DispatchAttemptId>,
        limit: usize,
    ) -> ProviderFuture<'_, Result<SavedRemoteObservationProgress, AutomaticTaskRunError>> {
        Box::pin(async move {
            assert_eq!(limit, 4);
            self.cursors.lock().unwrap().push(after);
            if self.hold {
                std::future::pending().await
            } else {
                Ok(self.pages.lock().unwrap().remove(0))
            }
        })
    }
}

fn attempt(byte: u8) -> DispatchAttemptId {
    DispatchAttemptId::from_bytes([byte; 16])
}

#[tokio::test(start_paused = true)]
async fn observer_advances_fairly_across_bounded_pages_and_resets_after_end() {
    let service = Arc::new(Observer {
        cursors: Mutex::new(Vec::new()),
        pages: Mutex::new(vec![
            SavedRemoteObservationProgress {
                next_after: Some(attempt(4)),
                reached_end: false,
                unavailable_candidates: 4,
            },
            SavedRemoteObservationProgress {
                next_after: Some(attempt(8)),
                reached_end: false,
                unavailable_candidates: 0,
            },
            SavedRemoteObservationProgress {
                next_after: Some(attempt(12)),
                reached_end: false,
                unavailable_candidates: 0,
            },
            SavedRemoteObservationProgress {
                next_after: Some(attempt(16)),
                reached_end: false,
                unavailable_candidates: 0,
            },
            SavedRemoteObservationProgress {
                next_after: Some(attempt(20)),
                reached_end: false,
                unavailable_candidates: 0,
            },
            SavedRemoteObservationProgress {
                next_after: Some(attempt(24)),
                reached_end: false,
                unavailable_candidates: 0,
            },
        ]),
        hold: false,
    });
    let stop = CancellationToken::new();
    let worker = tokio::spawn(run_automatic_taskrun_worker(service.clone(), stop.clone()));
    for _ in 0..2 {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
    }
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(60)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    let cursors = service.cursors.lock().unwrap().clone();
    assert_eq!(
        cursors,
        vec![
            None,
            Some(attempt(4)),
            Some(attempt(8)),
            Some(attempt(12)),
            Some(attempt(16)),
            Some(attempt(20)),
        ]
    );
    stop.cancel();
    worker.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn observer_shutdown_cancels_a_held_page_without_waiting_for_deadline() {
    let service = Arc::new(Observer {
        cursors: Mutex::new(Vec::new()),
        pages: Mutex::new(Vec::new()),
        hold: true,
    });
    let stop = CancellationToken::new();
    let worker = tokio::spawn(run_automatic_taskrun_worker(service.clone(), stop.clone()));
    tokio::task::yield_now().await;
    assert_eq!(service.cursors.lock().unwrap().len(), 1);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .expect("observer exits promptly on worker shutdown")
        .unwrap();
}
