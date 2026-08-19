    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";
    #[allow(dead_code)]
    const ID2: &str = "018f2e3a-7000-7000-8000-000000000001";
    #[allow(dead_code)]
    const ID3: &str = "018f2e3a-7000-7000-8000-000000000002";

    fn make_ids(count: u8) -> Vec<EventId> {
        let base: [u8; 16] = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        (0..count)
            .map(|i| {
                let mut bytes = base;
                bytes[15] = i;
                EventId::from_bytes(bytes)
            })
            .collect()
    }

    fn make_context() -> CommandContext {
        CommandContext {
            command_id: VALID_UUID.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("key-1").unwrap(),
            actor: Actor::new("test-actor").unwrap(),
        }
    }

    fn make_draft<E: Clone>(payload: E) -> DomainEventDraft<E> {
        let taskrun_id = VALID_UUID.parse().unwrap();
        let aggregate_id = AggregateId::TaskRun(taskrun_id);
        DomainEventDraft::new(
            aggregate_id.clone(),
            aggregate_id,
            1,
            Sensitivity::Public,
            payload,
        )
    }

    #[test]
    fn test_materialize_batch_single() {
        let drafts = vec![make_draft("event-1")];
        let ids = make_ids(1);
        let ctx = make_context();
        let result = materialize_batch(drafts, &ids, None, &ctx).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].event_id(), &ids[0]);
        assert_eq!(result[0].causation_id(), None);
        assert_eq!(result[0].payload(), &"event-1");
    }

    #[test]
    fn test_materialize_batch_chain() {
        let drafts = vec![make_draft(1u32), make_draft(2u32), make_draft(3u32)];
        let ids = make_ids(4);
        let ctx = make_context();
        let last_committed = Some(ids[0]); // use first id as last committed
        let result = materialize_batch(drafts, &ids[1..], last_committed, &ctx).unwrap();
        assert_eq!(result.len(), 3);
        // First: causation is last_committed
        assert_eq!(result[0].causation_id(), Some(&ids[0]));
        // Second: causation is previous event_id
        assert_eq!(result[1].causation_id(), Some(&ids[1]));
        // Third: causation is previous event_id
        assert_eq!(result[2].causation_id(), Some(&ids[2]));
    }

    #[test]
    fn test_materialize_batch_length_mismatch() {
        let drafts = vec![make_draft(1u32)];
        let ids = make_ids(2);
        let ctx = make_context();
        let err = materialize_batch(drafts, &ids, None, &ctx).unwrap_err();
        assert_eq!(
            err,
            BatchMaterializeError::LengthMismatch {
                drafts: 1,
                event_ids: 2
            }
        );
    }

    #[test]
    fn test_materialize_batch_duplicate_ids() {
        let drafts = vec![make_draft(1u32), make_draft(2u32)];
        let mut ids = make_ids(2);
        ids[1] = ids[0]; // duplicate
        let ctx = make_context();
        let err = materialize_batch(drafts, &ids, None, &ctx).unwrap_err();
        assert!(matches!(
            err,
            BatchMaterializeError::DuplicateEventId { .. }
        ));
    }

    #[test]
    fn test_sensitivity_values() {
        assert_ne!(Sensitivity::Public, Sensitivity::Internal);
        assert_ne!(Sensitivity::Public, Sensitivity::Sensitive);
    }

    #[test]
    fn test_actor_bounds() {
        assert!(Actor::new("").is_err());
        let too_long = "x".repeat(257);
        assert!(Actor::new(too_long).is_err());
        assert!(Actor::new("valid-actor").is_ok());
    }

    #[test]
    fn test_event_type_bounds() {
        assert!(EventType::new("").is_err());
        let too_long = "x".repeat(129);
        assert!(EventType::new(too_long).is_err());
        assert!(EventType::new("TaskRunCreated").is_ok());
    }

    #[test]
    fn test_into_envelope() {
        let draft = make_draft("envelope-test");
        let ids = make_ids(1);
        let ctx = make_context();
        let uncommitted = materialize_batch(vec![draft], &ids[..1], None, &ctx)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let ts = Timestamp::from_unix_micros(1000);
        let digest = IntegrityDigest::from_bytes([0; 32]);
        let envelope = uncommitted.into_envelope(1, ts, digest);
        assert_eq!(envelope.sequence(), 1);
        assert_eq!(*envelope.timestamp(), ts);
        assert_eq!(*envelope.integrity_digest(), digest);
        assert_eq!(*envelope.payload(), "envelope-test");
    }

    #[test]
    fn test_aggregate_type_display() {
        assert_eq!(AggregateType::TaskRun.to_string(), "TaskRun");
        assert_eq!(AggregateType::Conversation.to_string(), "Conversation");
        assert_eq!(AggregateType::Workspace.to_string(), "Workspace");
    }
