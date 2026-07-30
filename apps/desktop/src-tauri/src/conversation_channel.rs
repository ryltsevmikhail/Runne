use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use gocode_app_core::{AppCore, AppCoreError, ConversationTimelineUpdate};
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
    project_id: i64,
    control: Arc<SubscriptionControl>,
}

#[derive(Default)]
struct Registry {
    subscriptions: HashMap<String, SubscriptionRecord>,
    by_pair: HashMap<(String, i64), String>,
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

impl ConversationSubscriptionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                registry: Mutex::new(Registry::default()),
            }),
        }
    }

    /// Admits and starts one bounded native Conversation subscription.
    ///
    /// # Errors
    ///
    /// Returns only a closed error when the project, manager or quota is
    /// unavailable.
    pub fn subscribe<S>(
        &self,
        source: Arc<S>,
        project_id: i64,
        window_label: &str,
        on_update: Channel<ConversationChannelEvent>,
    ) -> Result<String, ConversationChannelError>
    where
        S: ConversationUpdateSource,
    {
        if project_id <= 0 || window_label.is_empty() {
            return Err(ConversationChannelError::unavailable());
        }
        let pair = (window_label.to_owned(), project_id);
        let (subscription_id, control) = {
            let mut registry = self
                .inner
                .registry
                .lock()
                .map_err(|_| ConversationChannelError::unavailable())?;
            if registry.shutting_down {
                return Err(ConversationChannelError::unavailable());
            }
            if registry.by_pair.contains_key(&pair) {
                return Err(ConversationChannelError::unavailable());
            }
            if registry.subscriptions.len() >= MAX_ACTIVE_SUBSCRIPTIONS {
                return Err(ConversationChannelError::unavailable());
            }
            let subscription_id = Uuid::now_v7().to_string();
            let control = Arc::new(SubscriptionControl::new());
            registry.by_pair.insert(pair, subscription_id.clone());
            registry.subscriptions.insert(
                subscription_id.clone(),
                SubscriptionRecord {
                    window_label: window_label.to_owned(),
                    project_id,
                    control: Arc::clone(&control),
                },
            );
            drop(registry);
            (subscription_id, control)
        };
        spawn_subscription(
            Arc::downgrade(&self.inner),
            subscription_id.clone(),
            source,
            project_id,
            control,
            on_update,
        );
        Ok(subscription_id)
    }

    /// Acknowledges exactly the update currently in flight for the caller.
    ///
    /// # Errors
    ///
    /// Unknown, cross-window, stale, regressing or future acknowledgements
    /// cancel the identified subscription and return a closed error.
    pub fn ack(
        &self,
        window_label: &str,
        subscription_id: &str,
        projection_revision: u64,
    ) -> Result<(), ConversationChannelError> {
        let control = {
            let registry = self
                .inner
                .registry
                .lock()
                .map_err(|_| ConversationChannelError::unavailable())?;
            let record = registry
                .subscriptions
                .get(subscription_id)
                .ok_or_else(ConversationChannelError::unavailable)?;
            if record.window_label != window_label {
                return Err(ConversationChannelError::unavailable());
            }
            let control = Arc::clone(&record.control);
            drop(registry);
            control
        };
        if control.acknowledge(projection_revision) {
            return Ok(());
        }
        Err(ConversationChannelError::unavailable())
    }

    /// Cancels exactly one caller-owned subscription.
    ///
    /// # Errors
    ///
    /// Returns a closed error when that subscription does not exist or belongs
    /// to another window.
    pub fn cancel(
        &self,
        window_label: &str,
        subscription_id: &str,
    ) -> Result<(), ConversationChannelError> {
        let control = {
            let mut registry = self
                .inner
                .registry
                .lock()
                .map_err(|_| ConversationChannelError::unavailable())?;
            let record = registry
                .subscriptions
                .get(subscription_id)
                .ok_or_else(ConversationChannelError::unavailable)?;
            if record.window_label != window_label {
                return Err(ConversationChannelError::unavailable());
            }
            let control = remove_subscription(&mut registry, subscription_id)
                .ok_or_else(ConversationChannelError::unavailable)?;
            drop(registry);
            control
        };
        control.cancel();
        Ok(())
    }

    pub fn cancel_window(&self, window_label: &str) {
        let controls = {
            let Ok(registry) = self.inner.registry.lock() else {
                return;
            };
            registry
                .subscriptions
                .values()
                .filter(|record| record.window_label == window_label)
                .map(|record| Arc::clone(&record.control))
                .collect::<Vec<_>>()
        };
        for control in controls {
            control.cancel();
        }
    }

    pub fn shutdown(&self) {
        let controls = {
            let Ok(mut registry) = self.inner.registry.lock() else {
                return;
            };
            registry.shutting_down = true;
            registry
                .subscriptions
                .values()
                .map(|record| Arc::clone(&record.control))
                .collect::<Vec<_>>()
        };
        for control in controls {
            control.cancel();
        }
    }
}

fn remove_subscription(
    registry: &mut Registry,
    subscription_id: &str,
) -> Option<Arc<SubscriptionControl>> {
    let record = registry.subscriptions.remove(subscription_id)?;
    registry
        .by_pair
        .remove(&(record.window_label, record.project_id));
    Some(record.control)
}

fn spawn_subscription<S>(
    manager: Weak<ManagerInner>,
    subscription_id: String,
    source: Arc<S>,
    project_id: i64,
    control: Arc<SubscriptionControl>,
    on_update: Channel<ConversationChannelEvent>,
) where
    S: ConversationUpdateSource,
{
    let (updates_tx, updates_rx) = mpsc::channel(MAX_QUEUED_UPDATES);
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let overflowed = Arc::new(AtomicBool::new(false));
    let overflow_changed = Arc::new(Notify::new());
    let callback_bytes = Arc::clone(&queued_bytes);
    let callback_overflowed = Arc::clone(&overflowed);
    let callback_overflow_changed = Arc::clone(&overflow_changed);
    let source_task = tokio::spawn(async move {
        source
            .subscribe(
                project_id,
                Box::new(move |update| {
                    let event = ConversationChannelEvent::update(update);
                    let Ok(bytes) = serde_json::to_vec(&event).map(|value| value.len()) else {
                        mark_overflow(&callback_overflowed, &callback_overflow_changed);
                        return;
                    };
                    if !reserve_bytes(&callback_bytes, bytes) {
                        mark_overflow(&callback_overflowed, &callback_overflow_changed);
                        return;
                    }
                    if updates_tx.try_send(QueuedUpdate { event, bytes }).is_err() {
                        callback_bytes.fetch_sub(bytes, Ordering::AcqRel);
                        mark_overflow(&callback_overflowed, &callback_overflow_changed);
                    }
                }),
            )
            .await
    });
    tokio::spawn(run_subscription(
        manager,
        subscription_id,
        control,
        on_update,
        updates_rx,
        queued_bytes,
        overflowed,
        overflow_changed,
        source_task,
    ));
}

struct QueuedUpdate {
    event: ConversationChannelEvent,
    bytes: usize,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_subscription(
    manager: Weak<ManagerInner>,
    subscription_id: String,
    control: Arc<SubscriptionControl>,
    on_update: Channel<ConversationChannelEvent>,
    mut updates_rx: mpsc::Receiver<QueuedUpdate>,
    queued_bytes: Arc<AtomicUsize>,
    overflowed: Arc<AtomicBool>,
    overflow_changed: Arc<Notify>,
    mut source_task: JoinHandle<Result<(), AppCoreError>>,
) {
    let mut source_error = None;
    let mut in_flight = None;
    let mut terminal_error = None;
    loop {
        if control.is_cancelled() {
            break;
        }
        if overflowed.load(Ordering::Acquire) {
            terminal_error =
                Some(ConversationChannelErrorCode::ConversationSubscriptionUnavailable);
            break;
        }

        if let Some((revision, sent_at)) = in_flight {
            tokio::select! {
                () = control.changed.notified() => {
                    if control.is_cancelled() {
                        break;
                    }
                    if !control.is_in_flight(revision) {
                        in_flight = None;
                    }
                }
                () = overflow_changed.notified() => {}
                result = &mut source_task, if source_error.is_none() => {
                    source_error = Some(map_source_result(result));
                }
                () = tokio::time::sleep_until(sent_at + ACK_TIMEOUT) => {
                    terminal_error =
                        Some(ConversationChannelErrorCode::ConversationSubscriptionUnavailable);
                    break;
                }
            }
            continue;
        }

        if source_error.is_some() {
            match updates_rx.try_recv() {
                Ok(update) => {
                    queued_bytes.fetch_sub(update.bytes, Ordering::AcqRel);
                    if !send_update(&control, &on_update, update.event, &mut in_flight) {
                        break;
                    }
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    let error = source_error.take().unwrap_or(
                        ConversationChannelErrorCode::ConversationSubscriptionUnavailable,
                    );
                    let _ = on_update.send(ConversationChannelEvent::error(error));
                    break;
                }
            }
        }

        tokio::select! {
            () = control.changed.notified() => {}
            () = overflow_changed.notified() => {}
            result = &mut source_task => {
                source_error = Some(map_source_result(result));
            }
            update = updates_rx.recv() => {
                if let Some(update) = update {
                    queued_bytes.fetch_sub(update.bytes, Ordering::AcqRel);
                    if !send_update(&control, &on_update, update.event, &mut in_flight) {
                        break;
                    }
                }
            }
        }
    }

    if source_error.is_none() {
        source_task.abort();
        let _ = source_task.await;
    }
    if let Some(error) = terminal_error {
        let _ = on_update.send(ConversationChannelEvent::error(error));
    }
    release_finished(&manager, &subscription_id);
}

fn send_update(
    control: &SubscriptionControl,
    on_update: &Channel<ConversationChannelEvent>,
    event: ConversationChannelEvent,
    in_flight: &mut Option<(u64, Instant)>,
) -> bool {
    let Some(revision) = event.projection_revision() else {
        return false;
    };
    if !control.set_in_flight(revision) {
        return false;
    }
    if on_update.send(event).is_err() {
        control.cancel();
        return false;
    }
    *in_flight = Some((revision, Instant::now()));
    true
}

fn map_source_result(
    result: Result<Result<(), AppCoreError>, tokio::task::JoinError>,
) -> ConversationChannelErrorCode {
    match result {
        Ok(Err(error)) => ConversationChannelErrorCode::from_app_core(&error),
        Ok(Ok(())) | Err(_) => ConversationChannelErrorCode::ConversationSubscriptionUnavailable,
    }
}

fn reserve_bytes(queued_bytes: &AtomicUsize, bytes: usize) -> bool {
    let mut current = queued_bytes.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(bytes) else {
            return false;
        };
        if next > MAX_QUEUED_BYTES {
            return false;
        }
        match queued_bytes.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn mark_overflow(overflowed: &AtomicBool, changed: &Notify) {
    overflowed.store(true, Ordering::Release);
    changed.notify_one();
}

fn release_finished(manager: &Weak<ManagerInner>, subscription_id: &str) {
    let Some(manager) = manager.upgrade() else {
        return;
    };
    let Ok(mut registry) = manager.registry.lock() else {
        return;
    };
    let _ = remove_subscription(&mut registry, subscription_id);
}
