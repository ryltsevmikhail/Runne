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
