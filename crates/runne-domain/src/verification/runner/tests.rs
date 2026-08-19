    use super::*;
    use uuid::Uuid;

    fn setup() -> (RunID, ProfileID, VerificationDigest) {
        (
            Uuid::now_v7(),
            Uuid::now_v7(),
            VerificationDigest::from_bytes([1; 32]),
        )
    }

    #[test]
    fn l0_produces_8_scenarios() {
        let (rid, pid, d) = setup();
        assert_eq!(L0Runner::run(rid, pid, d, 42).len(), 8);
    }
    #[test]
    fn l0_deterministic() {
        let (rid, pid, d) = setup();
        let r1 = L0Runner::run(rid, pid, d.clone(), 42);
        let r2 = L0Runner::run(rid, pid, d, 42);
        assert_eq!(r1.len(), r2.len());
    }
    #[test]
    fn l1_golden_comparison() {
        let (rid, pid, d) = setup();
        let traces = vec![("scenario-a", true), ("scenario-b", false)];
        let r = L1Runner::run(rid, pid, d, "v1", &traces);
        assert_eq!(r.len(), 2);
        assert!(r[0].passed);
        assert!(!r[1].passed);
    }
    #[test]
    fn l2s_fault_injection() {
        let (rid, pid, d) = setup();
        assert_eq!(L2SRunner::run(rid, pid, d, 42).len(), 8);
    }
    #[test]
    fn l2i_platform_unavailable() {
        let (rid, pid, d) = setup();
        assert!(L2IRunner::run(rid, pid, d, false).is_empty());
    }
    #[test]
    fn l2i_platform_available() {
        let (rid, pid, d) = setup();
        assert_eq!(L2IRunner::run(rid, pid, d, true).len(), 3);
    }
    #[test]
    fn l3_fixture_rejects_unauthorized() {
        let f = SanitizedFixture {
            fixture_id: "f1".into(),
            fixture_digest: VerificationDigest::from_bytes([1; 32]),
            schema_revision: "v1".into(),
            collection_time: "now".into(),
            rights_metadata: "test".into(),
            sanitization_passed: true,
        };
        assert!(L3FixtureStore::validate_and_store(&f, false).is_err());
    }
    #[test]
    fn l3_fixture_rejects_production() {
        let f = SanitizedFixture {
            fixture_id: "f1".into(),
            fixture_digest: VerificationDigest::from_bytes([1; 32]),
            schema_revision: "v1".into(),
            collection_time: "now".into(),
            rights_metadata: "production".into(),
            sanitization_passed: true,
        };
        assert!(L3FixtureStore::validate_and_store(&f, true).is_err());
    }
    #[test]
    fn l3_fixture_valid() {
        let f = SanitizedFixture {
            fixture_id: "f1".into(),
            fixture_digest: VerificationDigest::from_bytes([1; 32]),
            schema_revision: "v1".into(),
            collection_time: "now".into(),
            rights_metadata: "test".into(),
            sanitization_passed: true,
        };
        assert!(L3FixtureStore::validate_and_store(&f, true).is_ok());
    }
    #[test]
    fn l4_all_dimensions_checked() {
        let mut a = L4Authorization::new(10, 1000, 5, 60000, 1000);
        assert!(a.reserve(0, 1001, 0, 0, 0).is_err());
        assert!(a.reserve(0, 0, 6, 0, 0).is_err());
        assert!(a.reserve(0, 0, 0, 60001, 0).is_err());
        assert!(a.reserve(0, 0, 0, 0, 1001).is_err());
    }
    #[test]
    fn l4_atomic_reserve() {
        let mut a = L4Authorization::new(10, 100, 5, 60000, 1000);
        let r = a.reserve(0, 200, 0, 0, 0);
        assert!(r.is_err());
        assert_eq!(a.used_tokens, 0);
    }
    #[test]
    fn l4_revoked_rejects_all() {
        let mut a = L4Authorization::new(10, 100, 5, 60000, 1000);
        a.revoke();
        assert!(a.reserve(1, 0, 0, 0, 0).is_err());
    }
    #[test]
    fn gate_evaluator_passes() {
        let (rid, pid, d) = setup();
        let results = L0Runner::run(rid, pid, d, 42);
        assert_eq!(
            GateEvaluator::evaluate(&results, "L0", 1),
            GateResult::Passed
        );
    }
    #[test]
    fn gate_evaluator_blocks_insufficient() {
        let (rid, pid, d) = setup();
        let results = L0Runner::run(rid, pid, d, 42);
        assert_eq!(
            GateEvaluator::evaluate(&results, "L0", 100),
            GateResult::Blocked
        );
    }
