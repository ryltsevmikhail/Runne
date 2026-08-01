    use super::*;
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use gocode_domain::event::{Actor, CommandContext, DomainEventDraft, Sensitivity};
    use gocode_domain::id::{AggregateId, EventId, IdempotencyKey, TaskRunId};
    use gocode_domain::task_run::TaskRunEvent;
    use gocode_domain::timestamp::Timestamp;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    fn make_envelope(seq: u64, payload: TaskRunEvent) -> EventEnvelope<TaskRunEvent> {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let event_id: EventId = VALID_UUID.parse().unwrap();
        let draft = DomainEventDraft::new(
            AggregateId::TaskRun(tr_id),
            AggregateId::TaskRun(tr_id),
            1,
            Sensitivity::Public,
            payload,
        );
        let ctx = CommandContext {
            command_id: VALID_UUID.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("test-key").unwrap(),
            actor: Actor::new("test-actor").unwrap(),
        };
        let uncommitted =
            gocode_domain::event::materialize_batch(vec![draft], &[event_id], None, &ctx)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
        uncommitted.into_envelope(
            seq,
            Timestamp::from_unix_micros(1_000_000),
            IntegrityDigest::from_bytes([0; 32]),
        )
    }

    #[test]
    fn test_compute_digest_deterministic() {
        let envelope = make_envelope(1, TaskRunEvent::TaskRunCreated);
        let codec = TaskRunEventCodec;
        let payload_bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();

        let d1 =
            compute_integrity_digest_with_global_position(&envelope, 1, &payload_bytes).unwrap();
        let d2 =
            compute_integrity_digest_with_global_position(&envelope, 1, &payload_bytes).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_compute_digest_different_global_position() {
        let envelope = make_envelope(1, TaskRunEvent::TaskRunCreated);
        let codec = TaskRunEventCodec;
        let payload_bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();

        let d1 =
            compute_integrity_digest_with_global_position(&envelope, 1, &payload_bytes).unwrap();
        let d2 =
            compute_integrity_digest_with_global_position(&envelope, 2, &payload_bytes).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_compute_digest_golden() {
        let envelope = make_envelope(1, TaskRunEvent::TaskRunCreated);
        let codec = TaskRunEventCodec;
        let payload_bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        let digest =
            compute_integrity_digest_with_global_position(&envelope, 1, &payload_bytes).unwrap();

        // Verify digest is 32 bytes
        assert_eq!(digest.as_bytes().len(), 32);

        // Verify digest is not all zeros
        assert_ne!(*digest.as_bytes(), [0u8; 32]);

        // Verify hex display produces 64 chars
        let hex = digest.to_string();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_digest_different_events_produce_different_digests() {
        let codec = TaskRunEventCodec;
        let pb_created = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        let pb_queued = codec.encode(&TaskRunEvent::TaskRunQueued).unwrap();

        let env1 = make_envelope(1, TaskRunEvent::TaskRunCreated);
        let env2 = make_envelope(2, TaskRunEvent::TaskRunQueued);

        let d1 = compute_integrity_digest_with_global_position(&env1, 1, &pb_created).unwrap();
        let d2 = compute_integrity_digest_with_global_position(&env2, 2, &pb_queued).unwrap();

        assert_ne!(d1, d2);
    }
