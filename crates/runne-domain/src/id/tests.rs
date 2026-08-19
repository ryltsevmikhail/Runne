    use super::*;

    // valid UUIDv7: version nibble = 7, variant = 10xx
    const VALID_UUID_V7: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_parse_uuid_v7_valid() {
        let bytes = parse_uuid_v7(VALID_UUID_V7).unwrap();
        // version nibble
        assert_eq!(bytes[6] >> 4, 7);
        // variant
        assert_eq!(bytes[8] >> 6, 0b10);
    }

    #[test]
    fn test_parse_uuid_v7_empty() {
        assert_eq!(parse_uuid_v7(""), Err(InvalidIdReason::Empty));
    }

    #[test]
    fn test_parse_uuid_v7_wrong_length() {
        assert_eq!(
            parse_uuid_v7("too-short"),
            Err(InvalidIdReason::InvalidUuidFormat)
        );
    }

    #[test]
    fn test_parse_uuid_v7_wrong_hyphens() {
        // missing hyphens
        assert_eq!(
            parse_uuid_v7("018f2e3a70007000800000000000000000"),
            Err(InvalidIdReason::InvalidUuidFormat)
        );
    }

    #[test]
    fn test_parse_uuid_v7_wrong_version() {
        // UUIDv4 byte 6 nibble = 4
        let v4 = "018f2e3a-7000-4000-8000-000000000000";
        assert_eq!(
            parse_uuid_v7(v4),
            Err(InvalidIdReason::InvalidUuidVersion {
                expected: 7,
                actual: 4
            })
        );
    }

    #[test]
    fn test_parse_uuid_v7_wrong_variant() {
        // variant 0b00
        let bad_variant = "018f2e3a-7000-7000-0000-000000000000";
        assert_eq!(
            parse_uuid_v7(bad_variant),
            Err(InvalidIdReason::InvalidUuidVariant)
        );
    }

    #[test]
    fn test_parse_uuid_v7_invalid_hex() {
        assert_eq!(
            parse_uuid_v7("018f2e3a-7000-7000-8000-00000000000g"),
            Err(InvalidIdReason::InvalidUuidFormat)
        );
    }

    #[test]
    fn test_taskrun_id_from_str_and_display_roundtrip() {
        let id: TaskRunId = VALID_UUID_V7.parse().unwrap();
        assert_eq!(id.to_string(), VALID_UUID_V7);
    }

    #[test]
    fn test_all_newtypes_parse_identical_uuid() {
        let _: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let _: ConversationId = VALID_UUID_V7.parse().unwrap();
        let _: WorkspaceId = VALID_UUID_V7.parse().unwrap();
        let _: AttemptId = VALID_UUID_V7.parse().unwrap();
        let _: InvocationId = VALID_UUID_V7.parse().unwrap();
        let _: CheckpointId = VALID_UUID_V7.parse().unwrap();
        let _: PolicyId = VALID_UUID_V7.parse().unwrap();
        let _: ProcessId = VALID_UUID_V7.parse().unwrap();
        let _: EventId = VALID_UUID_V7.parse().unwrap();
        let _: CommandId = VALID_UUID_V7.parse().unwrap();
    }

    #[test]
    fn phase5_reference_ids_roundtrip_uuid_v7() {
        let _: ResultId = VALID_UUID_V7.parse().unwrap();
        let _: EffectId = VALID_UUID_V7.parse().unwrap();
        let _: BudgetReservationId = VALID_UUID_V7.parse().unwrap();
        let _: SecretRefId = VALID_UUID_V7.parse().unwrap();
        let _: ContextManifestId = VALID_UUID_V7.parse().unwrap();
        let _: ReconciliationRunId = VALID_UUID_V7.parse().unwrap();
        let _: PlanEvaluationId = VALID_UUID_V7.parse().unwrap();
        let _: WakeEvidenceId = VALID_UUID_V7.parse().unwrap();
    }

    #[test]
    fn test_newtypes_copy_and_eq() {
        let a: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn test_newtypes_ord() {
        let a: TaskRunId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
        let b: TaskRunId = "018f2e3a-7000-7000-8000-000000000002".parse().unwrap();
        assert!(a < b);
    }

    #[test]
    fn test_newtypes_hash() {
        use std::collections::HashSet;
        let a: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let b: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn test_newtype_debug() {
        let id: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let debug = format!("{:?}", id);
        assert!(debug.contains("TaskRunId"));
        assert!(debug.contains(VALID_UUID_V7));
    }

    #[test]
    fn test_idempotency_key_valid() {
        let key = IdempotencyKey::new("req-001").unwrap();
        assert_eq!(key.as_str(), "req-001");
        assert_eq!(key.to_string(), "req-001");
    }

    #[test]
    fn test_idempotency_key_empty() {
        assert_eq!(IdempotencyKey::new(""), Err(InvalidIdReason::Empty));
    }

    #[test]
    fn test_idempotency_key_too_long() {
        let long = "x".repeat(257);
        assert_eq!(
            IdempotencyKey::new(long),
            Err(InvalidIdReason::TooLong {
                max: 256,
                actual: 257
            })
        );
    }

    #[test]
    fn test_idempotency_key_control_char() {
        // NUL byte
        assert!(IdempotencyKey::new("req\u{0000}").is_err());
    }

    #[test]
    fn test_idempotency_key_clone_eq_hash() {
        use std::collections::HashSet;
        let k1 = IdempotencyKey::new("abc").unwrap();
        let k2 = IdempotencyKey::new("abc").unwrap();
        assert_eq!(k1, k2);
        let mut set = HashSet::new();
        set.insert(k1.clone());
        assert!(set.contains(&k2));
    }

    #[test]
    fn test_integrity_digest_display() {
        let digest = IntegrityDigest::from_bytes([0xab; 32]);
        let s = digest.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_aggregate_id_aggregate_type() {
        let id: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let agg = AggregateId::TaskRun(id);
        assert_eq!(agg.aggregate_type(), AggregateType::TaskRun);
    }

    #[test]
    fn test_aggregate_id_display() {
        let id: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let display = AggregateId::TaskRun(id).to_string();
        assert!(display.starts_with("taskrun:"));
    }

    #[test]
    fn test_parse_uuid_v7_extra_dashes_rejected() {
        // Extra dash in the tail — must be Err, not panic
        let result = parse_uuid_v7("018f2e3a-7000-7000-8000-000000-000000");
        assert!(matches!(result, Err(InvalidIdReason::InvalidUuidFormat)));
    }
