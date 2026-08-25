use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use runne_app_core::{AppCore, AppCoreError, CanonicalId, TaskRunTimelineUpdate};
use serde::Serialize;
use tauri::ipc::Channel;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use uuid::Uuid;

const MAX_ACTIVE_SUBSCRIPTIONS: usize = 8;
const MAX_QUEUED_UPDATES: usize = 64;
const MAX_QUEUED_BYTES: usize = 2 * 1024 * 1024;
const ACK_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRunChannelErrorCode {
    TaskRunSubscriptionUnavailable,
    RuntimeIncompatible,
    RuntimeRevoked,
    ReplayResyncRequired,
    RuntimeIdentityConflict,
    LocalProjectionUnavailable,
}

impl TaskRunChannelErrorCode {
    const fn from_app_core(error: &AppCoreError) -> Self {
        match error {
            AppCoreError::RuntimeIncompatible => Self::RuntimeIncompatible,
            AppCoreError::RuntimeRevoked => Self::RuntimeRevoked,
            AppCoreError::ReplayResyncRequired => Self::ReplayResyncRequired,
            AppCoreError::RuntimeIdentityConflict => Self::RuntimeIdentityConflict,
            AppCoreError::LocalProjectionUnavailable => Self::LocalProjectionUnavailable,
            _ => Self::TaskRunSubscriptionUnavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TaskRunChannelError {
    pub code: TaskRunChannelErrorCode,
}

impl TaskRunChannelError {
    pub(crate) const fn unavailable() -> Self {
        Self {
            code: TaskRunChannelErrorCode::TaskRunSubscriptionUnavailable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskRunChannelEvent {
    Update {
        #[serde(flatten)]
        update: TaskRunTimelineUpdate,
    },
    Error {
        code: TaskRunChannelErrorCode,
    },
}

pub trait TaskRunUpdateSource: Send + Sync + 'static {
    fn subscribe(
        self: Arc<Self>,
        task_run_id: String,
        on_update: Box<dyn FnMut(TaskRunTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>>;
}

impl TaskRunUpdateSource for AppCore {
    fn subscribe(
        self: Arc<Self>,
        task_run_id: String,
        mut on_update: Box<dyn FnMut(TaskRunTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        Box::pin(async move {
            self.subscribe_task_run_timeline(&task_run_id, &mut on_update)
                .await
        })
    }
}

include!("task_run_channel_parts/control.rs");

struct SubscriptionRecord {
    window_label: String,
    task_run_id: String,
    control: Arc<SubscriptionControl>,
    task: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct Registry {
    subscriptions: HashMap<String, SubscriptionRecord>,
    shutting_down: bool,
}

/// Owns bounded `TaskRun` renderer delivery; runtime replay ACK remains in
/// `AppCore`.
#[derive(Clone, Default)]
pub struct TaskRunSubscriptionManager {
    registry: Arc<Mutex<Registry>>,
}

include!("task_run_channel_parts/helpers.rs");
include!("task_run_channel_parts/run.rs");
include!("task_run_channel_parts/manager.rs");
