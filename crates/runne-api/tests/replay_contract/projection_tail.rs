#[test]
fn replay_projection_round_trips_failed_generation_without_fabricating_active_state() {
    let conversation_id = ConversationId::from_bytes(UUID_V7);
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000002".parse().unwrap();
    let taskrun_id = "018f2e3a-7000-7000-8000-000000000003".parse().unwrap();
    let attempt_id = "018f2e3a-7000-7000-8000-000000000004".parse().unwrap();
    let user_message_id = "018f2e3a-7000-7000-8000-000000000005".parse().unwrap();
    let idempotency = runne_domain::id::IdempotencyKey::new("failed-generation").unwrap();
    let event = |sequence, event_id, payload: runne_domain::conversation::ConversationEvent| {
        runne_domain::event::EventEnvelope::from_parts(
            event_id,
            runne_domain::id::AggregateId::Conversation(conversation_id),
            runne_domain::id::AggregateId::Conversation(conversation_id),
            None,
            runne_domain::id::CommandId::from_bytes([
                0x01,
                0x8f,
                0x2e,
                0x3a,
                0x70,
                0,
                0x70,
                0,
                0x80,
                0,
                0,
                0,
                0,
                0,
                0,
                sequence as u8,
            ]),
            idempotency.clone(),
            1,
            runne_domain::event::Actor::new("test").unwrap(),
            payload.sensitivity(),
            payload,
            sequence,
            runne_domain::timestamp::Timestamp::from_unix_micros(sequence as i64),
            runne_domain::id::IntegrityDigest::from_bytes([sequence as u8; 32]),
        )
    };
    for reason in [
        runne_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
        runne_domain::conversation::GenerationFailureReason::ProviderAccountingUnknown,
        runne_domain::conversation::GenerationFailureReason::Cancelled,
    ] {
        let aggregate = Conversation::replay(&[
            event(
                1,
                runne_domain::id::EventId::from_bytes([
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 10,
                ]),
                runne_domain::conversation::ConversationEvent::ConversationCreated { workspace_id },
            ),
            event(
                2,
                runne_domain::id::EventId::from_bytes([
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 11,
                ]),
                runne_domain::conversation::ConversationEvent::UserMessageAppended {
                    message_id: user_message_id,
                    taskrun_id,
                    attempt_id,
                    text: runne_domain::message::MessageText::new("hello").unwrap(),
                },
            ),
            event(
                3,
                runne_domain::id::EventId::from_bytes([
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 12,
                ]),
                runne_domain::conversation::ConversationEvent::GenerationFailed {
                    taskrun_id,
                    attempt_id,
                    reason,
                },
            ),
        ])
        .unwrap();
        let projection =
            runne_api::ReplayAggregateProjectionV1::from_conversation(&aggregate).unwrap();
        if reason == runne_domain::conversation::GenerationFailureReason::ProviderAccountingUnknown
        {
            let live_payload = runne_api::replay::CanonicalReplayPayloadV1::from(
                &runne_domain::conversation::ConversationEvent::GenerationFailed {
                    taskrun_id,
                    attempt_id,
                    reason,
                },
            );
            assert!(matches!(
                live_payload,
                runne_api::replay::CanonicalReplayPayloadV1::ConversationGenerationFailed {
                    reason,
                    ..
                } if reason == "provider_accounting_unknown"
            ));
        }
        assert!(
            runne_api::UnauthenticatedReplayProjectionV1::decode_conversation_bytes(
                projection.encoded_bytes()
            )
            .is_ok()
        );
    }
}

#[test]
fn replay_projection_round_trips_closed_task_run_with_taskrun_identity() {
    let task_run_id = runne_domain::id::TaskRunId::from_bytes(UUID_V7);
    let draft = runne_domain::event::DomainEventDraft::new(
        runne_domain::id::AggregateId::TaskRun(task_run_id),
        runne_domain::id::AggregateId::TaskRun(task_run_id),
        1,
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
    );
    let event = runne_domain::event::EventEnvelope::from_parts(
        runne_domain::id::EventId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 8,
        ]),
        draft.aggregate_id().clone(),
        draft.correlation_id().clone(),
        None,
        runne_domain::id::CommandId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 9,
        ]),
        runne_domain::id::IdempotencyKey::new("taskrun-projection").unwrap(),
        1,
        runne_domain::event::Actor::new("test").unwrap(),
        *draft.sensitivity(),
        draft.payload().clone(),
        1,
        runne_domain::timestamp::Timestamp::from_unix_micros(1),
        runne_domain::id::IntegrityDigest::from_bytes([5; 32]),
    );
    let task_run = TaskRun::replay(&[event]).unwrap();
    let projection = runne_api::ReplayAggregateProjectionV1::from_task_run(&task_run).unwrap();

    assert_eq!(projection.aggregate_kind(), ApiReplayAggregateKind::TaskRun);
    assert_eq!(projection.aggregate_id(), *task_run_id.as_bytes());
    let parsed = runne_api::UnauthenticatedReplayProjectionV1::decode_task_run_bytes(
        projection.encoded_bytes(),
    )
    .unwrap();
    assert_eq!(parsed.aggregate_id(), projection.aggregate_id());
    assert_eq!(
        runne_api::UnauthenticatedReplayProjectionV1::decode_conversation_bytes(
            projection.encoded_bytes()
        ),
        Err(ReplayContractError::InvalidProjection)
    );
}

#[test]
fn closed_projection_bytes_have_no_public_live_aggregate_restore_surface() {
    let api = include_str!("../../src/replay/baseline.rs");
    let conversation = include_str!("../../../runne-domain/src/conversation/snapshot.rs");
    let task_run = include_str!("../../../runne-domain/src/task_run/snapshot.rs");

    assert!(!api.contains("pub fn decode_conversation("));
    assert!(!api.contains("pub fn decode_task_run("));
    assert!(!conversation.contains("pub fn try_from_snapshot_v1"));
    assert!(!task_run.contains("pub fn try_from_snapshot_v1"));
}

#[test]
fn public_aggregate_scope_digest_matches_the_domain_canonical_transcript() {
    for (api_kind, domain_kind) in [
        (ApiReplayAggregateKind::TaskRun, 1),
        (ApiReplayAggregateKind::Conversation, 2),
    ] {
        let expected = runne_domain::replay::ReplayScope::Aggregate {
            aggregate_type: domain_kind,
            aggregate_id: UUID_V7,
        }
        .canonical_digest();
        assert_eq!(
            runne_api::canonical_aggregate_replay_scope_digest(api_kind, &UUID_V7),
            expected
        );
    }
}
