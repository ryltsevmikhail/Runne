use std::collections::BTreeSet;
use std::ffi::OsString;
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gocode_app_core::{
    AppCore, AppCoreError, ConversationMessageSummary, ConversationRecoveryDisposition,
    ConversationTimelineUpdate, RuntimeAvailability, RuntimeMode,
};
use gocode_desktop::conversation_channel::{
    ConversationChannelErrorCode, ConversationChannelEvent, ConversationSubscriptionManager,
    ConversationUpdateSource,
};
use gocode_desktop::{
    OwnedRuntimeLifecycle, RuntimeConnectionFuture, RuntimeLifecycleManager, select_runtime_mode,
};
use serde_json::Value;
use tauri::ipc::{Channel, InvokeResponseBody};

const PROJECT_ID: i64 = 7;

struct TrackedOwnedRuntime(Arc<AtomicBool>);

impl OwnedRuntimeLifecycle for TrackedOwnedRuntime {
    fn stop_on_explicit_quit(&self) {
        self.0.store(true, Ordering::Release);
    }
}

struct CountedOwnedRuntime(Arc<AtomicUsize>);

impl OwnedRuntimeLifecycle for CountedOwnedRuntime {
    fn stop_on_explicit_quit(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

struct ConnectingOwnedRuntime(Arc<AtomicUsize>);

impl OwnedRuntimeLifecycle for ConnectingOwnedRuntime {
    fn connect_runtime(&self) -> RuntimeConnectionFuture<'_> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Box::pin(async { Ok(RuntimeAvailability::Live) })
    }

    fn stop_on_explicit_quit(&self) {}
}

#[derive(Clone)]
struct ScriptedSource {
    updates: Vec<ConversationTimelineUpdate>,
    terminal: Terminal,
}

#[derive(Clone, Copy)]
enum Terminal {
    Pending,
    Unavailable,
    Incompatible,
    Revoked,
    ResyncRequired,
    IdentityConflict,
    ProjectionUnavailable,
}

struct TrackedPendingSource {
    started: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
}

struct StopGuard(Arc<AtomicBool>);

impl Drop for StopGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl ConversationUpdateSource for TrackedPendingSource {
    fn subscribe(
        self: Arc<Self>,
        _project_id: i64,
        _on_update: Box<dyn FnMut(ConversationTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        Box::pin(async move {
            let _guard = StopGuard(Arc::clone(&self.stopped));
            self.started.store(true, Ordering::Release);
            pending().await
        })
    }
}

impl ConversationUpdateSource for ScriptedSource {
    fn subscribe(
        self: Arc<Self>,
        _project_id: i64,
        mut on_update: Box<dyn FnMut(ConversationTimelineUpdate) + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppCoreError>> + Send>> {
        Box::pin(async move {
            for update in &self.updates {
                on_update(update.clone());
            }
            match self.terminal {
                Terminal::Pending => pending().await,
                Terminal::Unavailable => Err(AppCoreError::RuntimeUnavailable),
                Terminal::Incompatible => Err(AppCoreError::RuntimeIncompatible),
                Terminal::Revoked => Err(AppCoreError::RuntimeRevoked),
                Terminal::ResyncRequired => Err(AppCoreError::ReplayResyncRequired),
                Terminal::IdentityConflict => Err(AppCoreError::RuntimeIdentityConflict),
                Terminal::ProjectionUnavailable => Err(AppCoreError::LocalProjectionUnavailable),
            }
        })
    }
}

fn update(revision: u64, recovery: ConversationRecoveryDisposition) -> ConversationTimelineUpdate {
    ConversationTimelineUpdate {
        conversation_id: "018f2e3a-7000-7000-8000-000000000110".to_owned(),
        projection_revision: revision,
        stream_version: revision + 2,
        message: Some(ConversationMessageSummary {
            message_id: format!("018f2e3a-7000-7000-8000-{revision:012}"),
            role: "assistant".to_owned(),
            task_run_id: "018f2e3a-7000-7000-8000-000000000113".to_owned(),
            attempt_id: "018f2e3a-7000-7000-8000-000000000114".to_owned(),
            text: "bounded text".to_owned(),
            committed_at: 1_722_330_000_000_000,
        }),
        recovery,
    }
}

fn channel() -> (Channel<ConversationChannelEvent>, Arc<Mutex<Vec<Value>>>) {
    let values = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&values);
    let channel = Channel::new(move |body| {
        let InvokeResponseBody::Json(json) = body else {
            panic!("Conversation channel must send JSON");
        };
        captured
            .lock()
            .expect("captured messages")
            .push(serde_json::from_str(&json).expect("valid JSON"));
        Ok(())
    });
    (channel, values)
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .expect("JSON object")
        .keys()
        .map(String::as_str)
        .collect()
}

fn reject_forbidden_keys(value: &Value) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let normalized = key.to_ascii_lowercase();
                for forbidden in [
                    "cursor",
                    "token",
                    "authority",
                    "endpoint",
                    "binding",
                    "secret",
                    "certificate",
                    "credential",
                ] {
                    assert!(
                        !normalized.contains(forbidden),
                        "forbidden renderer key: {key}"
                    );
                }
                reject_forbidden_keys(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                reject_forbidden_keys(nested);
            }
        }
        _ => {}
    }
}

async fn wait_for_messages(messages: &Arc<Mutex<Vec<Value>>>, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if messages.lock().expect("messages").len() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("channel message");
}

async fn wait_for_replacement<S>(
    manager: &ConversationSubscriptionManager,
    source: Arc<S>,
    replaced: &str,
) -> String
where
    S: ConversationUpdateSource,
{
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (on_update, _) = channel();
            match manager.subscribe(Arc::clone(&source), PROJECT_ID, "main", on_update) {
                Ok(candidate) if candidate != replaced => return candidate,
                Ok(_) | Err(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .expect("subscription released")
}
