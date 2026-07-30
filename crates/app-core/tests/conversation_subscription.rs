mod support;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gocode_app_core::{
    ConversationMessageSummary, ConversationRecoveryDisposition, ConversationTimelineUpdate,
    RuntimeAvailability,
};
use support::Fixture;

#[test]
fn timeline_update_serializes_only_sanitized_projection_data() {
    let update = ConversationTimelineUpdate {
        conversation_id: "018f2e3a-7000-7000-8000-000000000110".to_owned(),
        projection_revision: 7,
        stream_version: 9,
        message: Some(ConversationMessageSummary {
            message_id: "018f2e3a-7000-7000-8000-000000000115".to_owned(),
            role: "assistant".to_owned(),
            task_run_id: "018f2e3a-7000-7000-8000-000000000113".to_owned(),
            attempt_id: "018f2e3a-7000-7000-8000-000000000114".to_owned(),
            text: "bounded text".to_owned(),
            committed_at: 1_722_330_000_000_000,
        }),
        recovery: ConversationRecoveryDisposition::Live,
    };

    let value = serde_json::to_value(update).expect("serialize update");
    let object = value.as_object().expect("object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "conversationId",
            "message",
            "projectionRevision",
            "recovery",
            "streamVersion",
        ]
    );
    let encoded = serde_json::to_string(object).expect("encode");
    for forbidden in [
        "cursor",
        "binding",
        "token",
        "endpoint",
        "secret",
        "authority",
        "session",
        "certificate",
        "credential",
    ] {
        assert!(!encoded.to_ascii_lowercase().contains(forbidden));
    }
}

#[tokio::test]
async fn inclusive_duplicate_is_acknowledged_without_ui_update() {
    let fixture = Fixture::opened().await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let acknowledged_before = fixture.runtime.ack_count();
    let subscription = fixture.subscribe(Arc::clone(&updates));

    fixture.runtime.wait_for_live(1).await;
    assert_eq!(fixture.runtime.ack_count(), acknowledged_before + 1);
    assert!(updates.lock().expect("updates").is_empty());
    subscription.abort();
}

#[tokio::test]
async fn disconnect_after_ack_uses_fresh_catch_up_and_recovers_without_duplicates() {
    let fixture = Fixture::opened().await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let subscription = fixture.subscribe(Arc::clone(&updates));
    fixture.runtime.wait_for_live(1).await;
    fixture.runtime.append_generation_failed();
    let acknowledged_after_first = fixture.runtime.ack_count() + 1;
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.runtime.ack_count() < acknowledged_after_first {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first live event acknowledged");
    let open_before_disconnect = fixture.runtime.open_count();

    fixture.runtime.disconnect_live();
    fixture.runtime.append_generation_failed();
    tokio::time::timeout(
        Duration::from_secs(2),
        fixture.runtime.wait_for_open(open_before_disconnect + 1),
    )
    .await
    .expect("fresh replay session opened from committed checkpoint");
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.runtime.ack_count() < acknowledged_after_first + 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("inclusive duplicate and new event acknowledged");

    let snapshot = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect("automatic recovery remains live");
    assert_eq!(snapshot.messages.len(), 0);
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Live
    );
    subscription.abort();
}

#[tokio::test]
async fn explicit_resync_resets_only_the_affected_scope_and_rebuilds_from_floor() {
    let fixture = Fixture::opened().await;
    fixture.runtime.force_retention_gap_once();
    let error = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("persisted cursor is outside retention");
    assert_eq!(error.to_string(), "replay_resync_required");
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::ResyncRequired
    );
    let create_before = fixture.runtime.create_count();

    let snapshot = fixture
        .core
        .resync_project_conversation(fixture.project_id)
        .await
        .expect("dedicated resync rebuild");

    assert_eq!(snapshot.messages.len(), 0);
    assert_eq!(fixture.runtime.create_count(), create_before);
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Live
    );
}

#[tokio::test]
async fn mutation_remains_live_while_subscription_reconcile_waits_and_race_applies_once() {
    let fixture = Fixture::opened().await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let primary_subscription = fixture.subscribe(Arc::clone(&updates));
    fixture.runtime.wait_for_live(1).await;
    fixture.runtime.block_generate();
    let core = Arc::clone(&fixture.core);
    let project_id = fixture.project_id;
    let send = tokio::spawn(async move { core.send_project_message(project_id, "hello").await });
    fixture.runtime.wait_for_generate(1).await;
    let open_before = fixture.runtime.open_count();
    let second_updates = Arc::new(Mutex::new(Vec::new()));
    let second_subscription = fixture.subscribe(second_updates);

    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            fixture.runtime.wait_for_open(open_before + 1)
        )
        .await
        .is_err(),
        "reconciliation must wait for the in-flight mutation lease"
    );
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Live
    );

    fixture.runtime.release_generate();
    let sent_snapshot = send.await.expect("send task").expect("send and reconcile");
    assert_eq!(sent_snapshot.messages.len(), 2);
    fixture.runtime.wait_for_open(open_before + 2).await;
    fixture.runtime.wait_for_live(2).await;

    let restored = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect("restore projection");
    assert_eq!(restored.messages.len(), 2);
    let updates = updates.lock().expect("updates");
    let message_ids = updates
        .iter()
        .filter_map(|update| update.message.as_ref())
        .map(|message| message.message_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        message_ids.iter().copied().collect::<HashSet<_>>().len(),
        message_ids.len()
    );
    assert!(message_ids.len() <= 2);
    drop(updates);
    primary_subscription.abort();
    second_subscription.abort();
}

#[test]
fn recovery_disposition_is_closed() {
    let dispositions = [
        ConversationRecoveryDisposition::Live,
        ConversationRecoveryDisposition::Reconnecting,
        ConversationRecoveryDisposition::Incompatible,
        ConversationRecoveryDisposition::Revoked,
        ConversationRecoveryDisposition::ResyncRequired,
        ConversationRecoveryDisposition::Fatal,
    ];
    assert_eq!(
        dispositions
            .iter()
            .map(|value| serde_json::to_string(value).expect("serialize"))
            .collect::<Vec<_>>(),
        [
            "\"live\"",
            "\"reconnecting\"",
            "\"incompatible\"",
            "\"revoked\"",
            "\"resync_required\"",
            "\"fatal\"",
        ]
    );
}
