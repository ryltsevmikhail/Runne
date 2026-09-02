use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use runne_app_core::{AppCore, AppCoreError, CanonicalId, ConversationTimelineUpdate};
use serde::Serialize;
use tauri::ipc::Channel;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use uuid::Uuid;

const MAX_ACTIVE_SUBSCRIPTIONS: usize = 8;
const MAX_QUEUED_UPDATES: usize = 64;
const MAX_QUEUED_BYTES: usize = 2 * 1024 * 1024;
const ACK_TIMEOUT: Duration = Duration::from_secs(45);

/// Closed renderer-safe error codes for Conversation subscriptions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationChannelErrorCode {
    ConversationSubscriptionUnavailable,
    RuntimeIncompatible,
    RuntimeRevoked,
    ReplayResyncRequired,
    RuntimeIdentityConflict,
    LocalProjectionUnavailable,
}

impl ConversationChannelErrorCode {
    pub const ALL: [Self; 6] = [
        Self::ConversationSubscriptionUnavailable,
        Self::RuntimeIncompatible,
        Self::RuntimeRevoked,
        Self::ReplayResyncRequired,
        Self::RuntimeIdentityConflict,
        Self::LocalProjectionUnavailable,
    ];

    const fn from_app_core(error: &AppCoreError) -> Self {
        match error {
            AppCoreError::RuntimeIncompatible => Self::RuntimeIncompatible,
            AppCoreError::RuntimeRevoked => Self::RuntimeRevoked,
            AppCoreError::ReplayResyncRequired => Self::ReplayResyncRequired,
            AppCoreError::RuntimeIdentityConflict => Self::RuntimeIdentityConflict,
            AppCoreError::LocalProjectionUnavailable => Self::LocalProjectionUnavailable,
            _ => Self::ConversationSubscriptionUnavailable,
        }
    }
}

/// Error envelope returned by subscription commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ConversationChannelError {
    pub code: ConversationChannelErrorCode,
}

impl ConversationChannelError {
    pub(crate) const fn unavailable() -> Self {
        Self {
            code: ConversationChannelErrorCode::ConversationSubscriptionUnavailable,
        }
    }
}

/// The only payload type delivered to the renderer Conversation channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConversationChannelEvent {
    Update {
        #[serde(flatten)]
        update: ConversationTimelineUpdate,
    },
    Error {
        code: ConversationChannelErrorCode,
    },
}

impl ConversationChannelEvent {
    #[must_use]
    pub const fn update(update: ConversationTimelineUpdate) -> Self {
        Self::Update { update }
    }

    #[must_use]
    pub const fn error(code: ConversationChannelErrorCode) -> Self {
        Self::Error { code }
    }

    const fn projection_revision(&self) -> Option<u64> {
        match self {
            Self::Update { update } => Some(update.projection_revision),
            Self::Error { .. } => None,
        }
    }
}

/// Native source boundary consumed by the bounded renderer delivery manager.
pub trait ConversationUpdateSource: Send + Sync + 'static {
    fn subscribe(
        self: Arc<Self>,
        project_id: i64,
        on_update: Box<dyn FnMut(ConversationTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>>;

    fn subscribe_workspace(
        self: Arc<Self>,
        workspace_id: String,
        on_update: Box<dyn FnMut(ConversationTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        let _ = (workspace_id, on_update);
        Box::pin(async { Err(AppCoreError::ProjectUnavailable) })
    }
}

impl ConversationUpdateSource for AppCore {
    fn subscribe(
        self: Arc<Self>,
        project_id: i64,
        mut on_update: Box<dyn FnMut(ConversationTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        Box::pin(async move {
            self.subscribe_project_conversation(project_id, &mut on_update)
                .await
        })
    }

    fn subscribe_workspace(
        self: Arc<Self>,
        workspace_id: String,
        mut on_update: Box<dyn FnMut(ConversationTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        Box::pin(async move {
            self.subscribe_workspace_conversation(&workspace_id, &mut on_update)
                .await
        })
    }
}

enum ConversationSubscriptionTarget {
    Project(i64),
    Workspace(String),
}

struct SubscriptionControl {
    state: Mutex<ControlState>,
    changed: Notify,
}

#[derive(Default)]
struct ControlState {
    cancelled: bool,
    in_flight: Option<u64>,
    last_acked: Option<u64>,
}

impl SubscriptionControl {
    fn new() -> Self {
        Self {
            state: Mutex::new(ControlState::default()),
            changed: Notify::new(),
        }
    }

    fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.cancelled = true;
        }
        self.changed.notify_one();
    }

    fn is_cancelled(&self) -> bool {
        self.state.lock().map_or(true, |state| state.cancelled)
    }

    fn set_in_flight(&self, revision: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.cancelled || state.in_flight.is_some() {
            return false;
        }
        state.in_flight = Some(revision);
        true
    }

    fn is_in_flight(&self, revision: u64) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.in_flight == Some(revision))
    }

    fn acknowledge(&self, revision: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let valid = !state.cancelled
            && state.in_flight == Some(revision)
            && state
                .last_acked
                .is_none_or(|acknowledged| revision > acknowledged);
        if !valid {
            state.cancelled = true;
            drop(state);
            self.changed.notify_one();
            return false;
        }
        state.in_flight = None;
        state.last_acked = Some(revision);
        drop(state);
        self.changed.notify_one();
        true
    }
}

struct SubscriptionRecord {
    window_label: String,
    conversation_key: String,
    control: Arc<SubscriptionControl>,
}

#[derive(Default)]
struct Registry {
    subscriptions: HashMap<String, SubscriptionRecord>,
    by_pair: HashMap<(String, String), String>,
    shutting_down: bool,
}

struct ManagerInner {
    registry: Mutex<Registry>,
}

/// Owns renderer subscription admission, acknowledgements and cancellation.
pub struct ConversationSubscriptionManager {
    inner: Arc<ManagerInner>,
}

impl Default for ConversationSubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

include!("conversation_channel_parts/manager.rs");
include!("conversation_channel_parts/spawn.rs");
include!("conversation_channel_parts/run.rs");
include!("conversation_channel_parts/helpers.rs");
