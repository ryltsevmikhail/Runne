#[test]
fn scope_digest_is_deterministic() {
    let scope = scope();

    assert_eq!(scope.canonical_digest(), scope.canonical_digest());
}

#[test]
fn scope_digest_differs_for_different_scopes() {
    let first = scope();
    let second = ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: [3; 16],
    };

    assert_ne!(first.canonical_digest(), second.canonical_digest());
}

#[test]
fn readiness_rejects_retained_event_that_cannot_fit_frame_plus_overhead() {
    let maximum_event_bytes =
        REPLAY_FRAME_CAPACITY_BYTES - REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES + 1;
    let manifest = DomainRetentionManifest::new(
        EventLogLineageId::from_bytes([4; 16]),
        0,
        Some(1),
        1,
        maximum_event_bytes,
        IntegrityDigest::from_bytes([9; 32]),
    )
    .unwrap();

    assert!(matches!(
        validate_replay_reader_capacity(
            &manifest,
            REPLAY_FRAME_CAPACITY_BYTES,
            REPLAY_PAGE_CAPACITY_BYTES,
            REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
        ),
        Err(ReplayError::Integrity(_))
    ));
}

#[test]
fn readiness_accepts_exact_frame_capacity_without_truncation() {
    let maximum_event_bytes =
        REPLAY_FRAME_CAPACITY_BYTES - REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES;
    let manifest = DomainRetentionManifest::new(
        EventLogLineageId::from_bytes([4; 16]),
        0,
        Some(1),
        1,
        maximum_event_bytes,
        IntegrityDigest::from_bytes([9; 32]),
    )
    .unwrap();

    validate_replay_reader_capacity(
        &manifest,
        REPLAY_FRAME_CAPACITY_BYTES,
        REPLAY_PAGE_CAPACITY_BYTES,
        REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
    )
    .unwrap();
}

#[test]
fn readiness_rejects_empty_inventory_when_future_append_limit_exceeds_reader() {
    let manifest = DomainRetentionManifest::new(
        EventLogLineageId::from_bytes([4; 16]),
        0,
        None,
        0,
        0,
        IntegrityDigest::from_bytes([9; 32]),
    )
    .unwrap();

    assert!(matches!(
        validate_replay_reader_capacity(
            &manifest,
            REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES + 1,
            REPLAY_PAGE_CAPACITY_BYTES,
            REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
        ),
        Err(ReplayError::Integrity(_))
    ));
}

#[test]
fn writer_rejects_exact_canonical_event_expanded_by_json_escaping() {
    let mut replay_event = event();
    replay_event.aggregate_type = 2;
    replay_event.correlation_type = 2;
    let payload = ConversationEvent::UserMessageAppended {
        message_id: MessageId::from_bytes([0x11; 16]),
        taskrun_id: TaskRunId::from_bytes([0x22; 16]),
        attempt_id: AttemptId::from_bytes([0x33; 16]),
        text: MessageText::new("\0".repeat(MAX_MESSAGE_TEXT_BYTES)).unwrap(),
    };

    let actual = measured_conversation_replay_event_bytes(&replay_event, &payload).unwrap();

    assert!(actual > REPLAY_EVENT_VARIABLE_MAX_BYTES);
    assert!(matches!(
        validate_replay_writer_event_size(actual),
        Err(ReplayError::Integrity(_))
    ));
}

#[test]
fn writer_rejects_durable_payload_whose_hex_transport_exceeds_frame_budget() {
    let mut replay_event = event();
    replay_event.payload = vec![0xab; (REPLAY_EVENT_VARIABLE_MAX_BYTES / 2) + 1];

    let actual =
        measured_taskrun_replay_event_bytes(&replay_event, &TaskRunEvent::TaskRunCreated).unwrap();

    assert!(actual > REPLAY_EVENT_VARIABLE_MAX_BYTES);
    assert!(matches!(
        validate_replay_writer_event_size(actual),
        Err(ReplayError::Integrity(_))
    ));
}
