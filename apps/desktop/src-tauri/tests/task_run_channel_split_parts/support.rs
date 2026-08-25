use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use runne_app_core::{AppCoreError, TaskRunRecoveryDisposition, TaskRunTimelineUpdate};
use runne_desktop::task_run_channel::{
    TaskRunChannelEvent, TaskRunSubscriptionManager, TaskRunUpdateSource,
};
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::sync::oneshot;

const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000210";

#[derive(Clone, Copy)]
enum Outcome {
    Complete,
    Error,
    Resync,
    Pending,
}
struct Source(Outcome);

struct BurstSource {
    updates: u64,
    pending: bool,
}

struct BlockingSource {
    started: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
    terminated: Arc<AtomicBool>,
}

struct Termination(Arc<AtomicBool>);

impl Drop for Termination {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl TaskRunUpdateSource for Source {
    fn subscribe(
        self: Arc<Self>,
        _id: String,
        mut update: Box<dyn FnMut(TaskRunTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        Box::pin(async move {
            update(TaskRunTimelineUpdate {
                task_run_id: TASK_RUN_ID.into(),
                projection_revision: 1,
                stream_version: 1,
                entry: None,
                recovery: TaskRunRecoveryDisposition::Live,
            });
            match self.0 {
                Outcome::Complete => Ok(()),
                Outcome::Error => Err(AppCoreError::RuntimeUnavailable),
                Outcome::Resync => Err(AppCoreError::ReplayResyncRequired),
                Outcome::Pending => pending().await,
            }
        })
    }
}

impl TaskRunUpdateSource for BlockingSource {
    fn subscribe(
        self: Arc<Self>,
        _id: String,
        _update: Box<dyn FnMut(TaskRunTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        let started = self.started.lock().expect("started lock").take();
        let release = self.release.lock().expect("release lock").take();
        let terminated = Arc::clone(&self.terminated);
        Box::pin(async move {
            let _termination = Termination(terminated);
            started
                .expect("one subscription")
                .send(())
                .expect("start signal");
            tokio::task::block_in_place(|| {
                release.expect("release receiver").recv().expect("release");
            });
            Ok(())
        })
    }
}

impl TaskRunUpdateSource for BurstSource {
    fn subscribe(
        self: Arc<Self>,
        _id: String,
        mut update: Box<dyn FnMut(TaskRunTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        Box::pin(async move {
            for revision in 1..=self.updates {
                update(TaskRunTimelineUpdate {
                    task_run_id: TASK_RUN_ID.into(),
                    projection_revision: revision,
                    stream_version: revision,
                    entry: None,
                    recovery: TaskRunRecoveryDisposition::Live,
                });
            }
            if self.pending {
                pending::<()>().await;
            }
            Ok(())
        })
    }
}

fn channel() -> Channel<TaskRunChannelEvent> {
    Channel::new(|body| {
        let InvokeResponseBody::Json(_) = body else {
            panic!("TaskRun channel must send JSON")
        };
        Ok(())
    })
}

fn counting_channel(deliveries: Arc<AtomicUsize>) -> Channel<TaskRunChannelEvent> {
    Channel::new(move |body| {
        let InvokeResponseBody::Json(_) = body else {
            panic!("TaskRun channel must send JSON")
        };
        deliveries.fetch_add(1, Ordering::AcqRel);
        Ok(())
    })
}

fn recording_channel(events: Arc<Mutex<Vec<String>>>) -> Channel<TaskRunChannelEvent> {
    Channel::new(move |body| {
        let InvokeResponseBody::Json(event) = body else {
            panic!("TaskRun channel must send JSON")
        };
        events.lock().expect("events lock").push(event);
        Ok(())
    })
}

async fn wait_for_deliveries(deliveries: &AtomicUsize, count: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while deliveries.load(Ordering::Acquire) < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("channel delivery");
}

async fn wait_for_slot(manager: &TaskRunSubscriptionManager, source: Arc<Source>) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Ok(id) = manager.subscribe(Arc::clone(&source), TASK_RUN_ID, "main", channel()) {
                return id;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("released slot")
}
