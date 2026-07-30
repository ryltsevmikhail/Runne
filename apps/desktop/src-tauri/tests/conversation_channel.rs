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

#[test]
fn every_update_and_error_variant_has_an_exact_safe_wire_shape() {
    for recovery in [
        ConversationRecoveryDisposition::Live,
        ConversationRecoveryDisposition::Reconnecting,
        ConversationRecoveryDisposition::Incompatible,
        ConversationRecoveryDisposition::Revoked,
        ConversationRecoveryDisposition::ResyncRequired,
        ConversationRecoveryDisposition::Fatal,
    ] {
        let value = serde_json::to_value(ConversationChannelEvent::update(update(7, recovery)))
            .expect("serialize update");
        assert_eq!(
            keys(&value),
            BTreeSet::from([
                "conversationId",
                "kind",
                "message",
                "projectionRevision",
                "recovery",
                "streamVersion",
            ])
        );
        assert_eq!(
            keys(&value["message"]),
            BTreeSet::from([
                "attemptId",
                "committedAt",
                "messageId",
                "role",
                "taskRunId",
                "text",
            ])
        );
        reject_forbidden_keys(&value);
    }

    for code in ConversationChannelErrorCode::ALL {
        let value =
            serde_json::to_value(ConversationChannelEvent::error(code)).expect("serialize error");
        assert_eq!(keys(&value), BTreeSet::from(["code", "kind"]));
        reject_forbidden_keys(&value);
    }
}

#[tokio::test]
async fn sends_only_one_update_until_the_exact_revision_is_acknowledged() {
    let manager = ConversationSubscriptionManager::new();
    let source = Arc::new(ScriptedSource {
        updates: vec![
            update(1, ConversationRecoveryDisposition::Live),
            update(2, ConversationRecoveryDisposition::Live),
        ],
        terminal: Terminal::Pending,
    });
    let (on_update, messages) = channel();
    let subscription_id = manager
        .subscribe(source, PROJECT_ID, "main", on_update)
        .expect("subscribe");

    wait_for_messages(&messages, 1).await;
    tokio::task::yield_now().await;
    assert_eq!(messages.lock().expect("messages").len(), 1);
    assert_eq!(
        messages.lock().expect("messages")[0]["projectionRevision"],
        1
    );

    manager
        .ack("main", &subscription_id, 1)
        .expect("ack exact revision");
    wait_for_messages(&messages, 2).await;
    assert_eq!(
        messages.lock().expect("messages")[1]["projectionRevision"],
        2
    );
}

#[tokio::test]
async fn duplicate_start_is_rejected_instead_of_orphaning_the_new_channel() {
    let manager = ConversationSubscriptionManager::new();
    let source = Arc::new(ScriptedSource {
        updates: vec![
            update(1, ConversationRecoveryDisposition::Live),
            update(2, ConversationRecoveryDisposition::Live),
        ],
        terminal: Terminal::Pending,
    });
    let (original_channel, original_messages) = channel();
    let subscription_id = manager
        .subscribe(Arc::clone(&source), PROJECT_ID, "main", original_channel)
        .expect("initial subscribe");
    wait_for_messages(&original_messages, 1).await;

    let (duplicate_channel, duplicate_messages) = channel();
    let error = manager
        .subscribe(source, PROJECT_ID, "main", duplicate_channel)
        .expect_err("live duplicate must not return an orphaned ID");
    assert_eq!(
        error.code,
        ConversationChannelErrorCode::ConversationSubscriptionUnavailable
    );

    manager
        .ack("main", &subscription_id, 1)
        .expect("original channel remains authoritative");
    wait_for_messages(&original_messages, 2).await;
    assert!(duplicate_messages.lock().expect("messages").is_empty());
}

#[tokio::test]
async fn duplicate_and_global_admission_limits_are_released_by_exact_cancel() {
    let manager = ConversationSubscriptionManager::new();
    let source = Arc::new(ScriptedSource {
        updates: Vec::new(),
        terminal: Terminal::Pending,
    });
    let mut subscriptions = Vec::new();

    for project_id in 1..=8 {
        let (on_update, _) = channel();
        subscriptions.push(
            manager
                .subscribe(Arc::clone(&source), project_id, "main", on_update)
                .expect("within quota"),
        );
    }
    let (duplicate_channel, _) = channel();
    let duplicate_error = manager
        .subscribe(Arc::clone(&source), 1, "main", duplicate_channel)
        .expect_err("duplicate consumes no extra quota");
    assert_eq!(
        duplicate_error.code,
        ConversationChannelErrorCode::ConversationSubscriptionUnavailable
    );

    let (over_quota_channel, _) = channel();
    let error = manager
        .subscribe(Arc::clone(&source), 9, "main", over_quota_channel)
        .expect_err("ninth unique subscription rejected");
    assert_eq!(
        error.code,
        ConversationChannelErrorCode::ConversationSubscriptionUnavailable
    );

    let project_subscription = &subscriptions[usize::try_from(PROJECT_ID - 1).expect("index")];
    manager
        .cancel("main", project_subscription)
        .expect("cancel exact ID");
    let replacement = wait_for_replacement(&manager, source, project_subscription).await;
    assert_ne!(replacement, *project_subscription);
}

#[tokio::test]
async fn explicit_cancel_releases_admission_before_returning_success() {
    let manager = ConversationSubscriptionManager::new();
    let started = Arc::new(AtomicBool::new(false));
    let stopped = Arc::new(AtomicBool::new(false));
    let source = Arc::new(TrackedPendingSource {
        started: Arc::clone(&started),
        stopped: Arc::clone(&stopped),
    });
    let (on_update, _) = channel();
    let subscription_id = manager
        .subscribe(source, PROJECT_ID, "main", on_update)
        .expect("subscribe");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("native source started");

    manager
        .cancel("main", &subscription_id)
        .expect("cancel exact ID");
    let replacement_source = Arc::new(ScriptedSource {
        updates: Vec::new(),
        terminal: Terminal::Pending,
    });
    let (replacement_channel, _) = channel();
    let replacement = manager
        .subscribe(replacement_source, PROJECT_ID, "main", replacement_channel)
        .expect("cancel releases pair before returning");
    assert_ne!(replacement, subscription_id);

    tokio::time::timeout(Duration::from_secs(2), async {
        while !stopped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("native source stopped");
}

#[tokio::test]
async fn invalid_or_regressing_ack_cancels_and_releases_the_pair() {
    let manager = ConversationSubscriptionManager::new();
    let source = Arc::new(ScriptedSource {
        updates: vec![update(3, ConversationRecoveryDisposition::Live)],
        terminal: Terminal::Pending,
    });
    let (on_update, messages) = channel();
    let subscription_id = manager
        .subscribe(Arc::clone(&source), PROJECT_ID, "main", on_update)
        .expect("subscribe");
    wait_for_messages(&messages, 1).await;

    let error = manager
        .ack("main", &subscription_id, 2)
        .expect_err("wrong revision rejected");
    assert_eq!(
        error.code,
        ConversationChannelErrorCode::ConversationSubscriptionUnavailable
    );

    let replacement = wait_for_replacement(&manager, source, &subscription_id).await;
    assert_ne!(replacement, subscription_id);
}

#[tokio::test]
async fn regressing_ack_after_progress_cancels_and_releases_the_pair() {
    let manager = ConversationSubscriptionManager::new();
    let source = Arc::new(ScriptedSource {
        updates: vec![
            update(3, ConversationRecoveryDisposition::Live),
            update(4, ConversationRecoveryDisposition::Live),
        ],
        terminal: Terminal::Pending,
    });
    let (on_update, messages) = channel();
    let subscription_id = manager
        .subscribe(Arc::clone(&source), PROJECT_ID, "main", on_update)
        .expect("subscribe");
    wait_for_messages(&messages, 1).await;
    manager.ack("main", &subscription_id, 3).expect("first ack");
    wait_for_messages(&messages, 2).await;

    manager
        .ack("main", &subscription_id, 3)
        .expect_err("regressing ack rejected");
    let replacement = wait_for_replacement(&manager, source, &subscription_id).await;
    assert_ne!(replacement, subscription_id);
}

#[tokio::test(start_paused = true)]
async fn ack_silence_cancels_after_45_seconds_and_releases_the_pair() {
    let manager = ConversationSubscriptionManager::new();
    let source = Arc::new(ScriptedSource {
        updates: vec![update(1, ConversationRecoveryDisposition::Live)],
        terminal: Terminal::Pending,
    });
    let (on_update, messages) = channel();
    let first = manager
        .subscribe(Arc::clone(&source), PROJECT_ID, "main", on_update)
        .expect("subscribe");
    wait_for_messages(&messages, 1).await;

    tokio::time::advance(Duration::from_secs(46)).await;
    tokio::task::yield_now().await;
    wait_for_messages(&messages, 2).await;

    assert_eq!(
        messages.lock().expect("messages")[1],
        serde_json::json!({
            "kind": "error",
            "code": "conversation_subscription_unavailable",
        })
    );

    let replacement = wait_for_replacement(&manager, source, &first).await;
    assert_ne!(replacement, first);
}

#[tokio::test]
async fn queue_count_or_byte_overflow_cancels_and_releases_the_pair() {
    for updates in [
        (1..=65)
            .map(|revision| update(revision, ConversationRecoveryDisposition::Live))
            .collect::<Vec<_>>(),
        (1..=33)
            .map(|revision| {
                let mut update = update(revision, ConversationRecoveryDisposition::Live);
                update.message.as_mut().expect("message").text = "x".repeat(64 * 1024);
                update
            })
            .collect::<Vec<_>>(),
    ] {
        let manager = ConversationSubscriptionManager::new();
        let source = Arc::new(ScriptedSource {
            updates,
            terminal: Terminal::Pending,
        });
        let (on_update, messages) = channel();
        let first = manager
            .subscribe(Arc::clone(&source), PROJECT_ID, "main", on_update)
            .expect("subscribe");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if messages.lock().expect("messages").iter().any(|message| {
                    *message
                        == serde_json::json!({
                            "kind": "error",
                            "code": "conversation_subscription_unavailable",
                        })
                }) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("renderer-visible overflow recovery");
        let replacement = wait_for_replacement(&manager, source, &first).await;
        assert_ne!(replacement, first);
    }
}

#[tokio::test]
async fn channel_failure_window_destruction_and_shutdown_release_native_ownership() {
    let manager = ConversationSubscriptionManager::new();
    let source = Arc::new(ScriptedSource {
        updates: vec![update(1, ConversationRecoveryDisposition::Live)],
        terminal: Terminal::Pending,
    });
    let failed_channel = Channel::new(|_| Err(tauri::Error::FailedToReceiveMessage));
    let failed = manager
        .subscribe(Arc::clone(&source), PROJECT_ID, "main", failed_channel)
        .expect("subscribe");
    let after_failure = wait_for_replacement(&manager, Arc::clone(&source), &failed).await;
    assert_ne!(after_failure, failed);

    manager.cancel_window("main");
    wait_for_replacement(&manager, Arc::clone(&source), &after_failure).await;

    manager.shutdown();
    let (after_shutdown_channel, _) = channel();
    let error = manager
        .subscribe(source, PROJECT_ID + 1, "main", after_shutdown_channel)
        .expect_err("shutdown closes admission");
    assert_eq!(
        error.code,
        ConversationChannelErrorCode::ConversationSubscriptionUnavailable
    );
}

#[tokio::test]
async fn source_errors_are_mapped_to_the_closed_code_set() {
    for (terminal, expected) in [
        (
            Terminal::Unavailable,
            ConversationChannelErrorCode::ConversationSubscriptionUnavailable,
        ),
        (
            Terminal::Incompatible,
            ConversationChannelErrorCode::RuntimeIncompatible,
        ),
        (
            Terminal::Revoked,
            ConversationChannelErrorCode::RuntimeRevoked,
        ),
        (
            Terminal::ResyncRequired,
            ConversationChannelErrorCode::ReplayResyncRequired,
        ),
        (
            Terminal::IdentityConflict,
            ConversationChannelErrorCode::RuntimeIdentityConflict,
        ),
        (
            Terminal::ProjectionUnavailable,
            ConversationChannelErrorCode::LocalProjectionUnavailable,
        ),
    ] {
        let manager = ConversationSubscriptionManager::new();
        let source = Arc::new(ScriptedSource {
            updates: Vec::new(),
            terminal,
        });
        let (on_update, messages) = channel();
        manager
            .subscribe(source, PROJECT_ID, "main", on_update)
            .expect("subscribe");
        wait_for_messages(&messages, 1).await;
        assert_eq!(
            messages.lock().expect("messages")[0],
            serde_json::json!({
                "kind": "error",
                "code": expected,
            })
        );
    }
}

#[test]
fn explicit_quit_leaves_external_runtime_uncontrolled_and_calls_only_owned_lifecycle() {
    let stopped = Arc::new(AtomicBool::new(false));
    RuntimeLifecycleManager::external().explicit_quit();
    assert!(!stopped.load(Ordering::Acquire));

    RuntimeLifecycleManager::bundled(Arc::new(TrackedOwnedRuntime(Arc::clone(&stopped))))
        .explicit_quit();
    assert!(stopped.load(Ordering::Acquire));
}

#[test]
fn explicit_quit_fences_admission_and_runs_owned_lifecycle_once() {
    let stops = Arc::new(AtomicUsize::new(0));
    let lifecycle =
        RuntimeLifecycleManager::bundled(Arc::new(CountedOwnedRuntime(Arc::clone(&stops))));

    assert!(lifecycle.begin_explicit_quit());
    assert!(lifecycle.is_shutting_down());
    lifecycle.stop_owned_runtime();
    assert!(!lifecycle.begin_explicit_quit());
    assert_eq!(stops.load(Ordering::Acquire), 1);
}

#[test]
fn bundled_is_default_and_external_mode_requires_an_explicit_flag() {
    assert_eq!(
        select_runtime_mode(Vec::<OsString>::new()).expect("default mode"),
        RuntimeMode::Bundled
    );
    assert_eq!(
        select_runtime_mode([OsString::from("--external-runtime")]).expect("external mode"),
        RuntimeMode::ExternalLocal
    );
    assert!(
        select_runtime_mode([
            OsString::from("--external-runtime"),
            OsString::from("--bundled-runtime"),
        ])
        .is_err()
    );
}

#[tokio::test]
async fn bundled_connection_never_falls_back_and_quit_fences_connector_admission() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");

    assert!(
        RuntimeLifecycleManager::bundled_unavailable()
            .connect_runtime(&core)
            .await
            .is_err()
    );

    let connects = Arc::new(AtomicUsize::new(0));
    let lifecycle =
        RuntimeLifecycleManager::bundled(Arc::new(ConnectingOwnedRuntime(Arc::clone(&connects))));
    assert_eq!(
        lifecycle.connect_runtime(&core).await.expect("connect"),
        RuntimeAvailability::Live
    );
    assert_eq!(connects.load(Ordering::Acquire), 1);

    assert!(lifecycle.begin_explicit_quit());
    assert!(lifecycle.connect_runtime(&core).await.is_err());
    assert_eq!(connects.load(Ordering::Acquire), 1);
}
