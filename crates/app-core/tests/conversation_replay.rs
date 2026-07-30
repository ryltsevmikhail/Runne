use gocode_app_core::{ConversationRecoveryDisposition, ConversationSnapshot};

#[test]
fn snapshot_carries_projection_revision_and_closed_recovery() {
    let snapshot = ConversationSnapshot {
        conversation_id: "018f2e3a-7000-7000-8000-000000000110".to_owned(),
        projection_revision: 3,
        stream_version: 3,
        messages: Vec::new(),
        recovery: ConversationRecoveryDisposition::Live,
    };

    assert_eq!(snapshot.projection_revision, 3);
    assert_eq!(snapshot.recovery, ConversationRecoveryDisposition::Live);
    let value = serde_json::to_value(snapshot).expect("serialize snapshot");
    assert_eq!(
        value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "conversationId",
            "messages",
            "projectionRevision",
            "recovery",
            "streamVersion",
        ]
    );
}
