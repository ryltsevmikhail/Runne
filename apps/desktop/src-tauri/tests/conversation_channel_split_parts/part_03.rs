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
