    use super::*;
    use crate::verification::digest::VerificationDigest;

    fn test_digest(b: u8) -> VerificationDigest {
        VerificationDigest::from_bytes([b; 32])
    }

    #[test]
    fn all_passed() {
        assert_eq!(
            aggregate_plan_result(&[("G1".into(), GateResult::Passed)]),
            PlanResult::Passed
        );
    }
    #[test]
    fn any_failed() {
        assert_eq!(
            aggregate_plan_result(&[
                ("G1".into(), GateResult::Passed),
                ("G2".into(), GateResult::Failed)
            ]),
            PlanResult::Failed
        );
    }
    #[test]
    fn any_blocked() {
        assert_eq!(
            aggregate_plan_result(&[
                ("G1".into(), GateResult::Passed),
                ("G2".into(), GateResult::Blocked)
            ]),
            PlanResult::Blocked
        );
    }
    #[test]
    fn failed_wins_over_blocked() {
        assert_eq!(
            aggregate_plan_result(&[
                ("G1".into(), GateResult::Failed),
                ("G2".into(), GateResult::Blocked)
            ]),
            PlanResult::Failed
        );
    }

    // GateHeadSnapshot tests
    #[test]
    fn gate_head_snapshot_verify_ok() {
        let d = test_digest(1);
        let mut heads = HashMap::new();
        heads.insert(
            "G1".into(),
            GateEvaluationRef {
                evaluation_ref_id: uuid::Uuid::now_v7(),
                evaluation_digest: d.clone(),
                generation: 1,
            },
        );
        let snapshot = GateHeadSnapshot::capture(&heads);
        assert!(snapshot.verify_against_current(&heads).is_ok());
    }

    #[test]
    fn gate_head_snapshot_detect_stale() {
        let mut heads_before = HashMap::new();
        heads_before.insert(
            "G1".into(),
            GateEvaluationRef {
                evaluation_ref_id: uuid::Uuid::now_v7(),
                evaluation_digest: test_digest(1),
                generation: 1,
            },
        );
        let snapshot = GateHeadSnapshot::capture(&heads_before);
        let mut heads_after = HashMap::new();
        heads_after.insert(
            "G1".into(),
            GateEvaluationRef {
                evaluation_ref_id: uuid::Uuid::now_v7(),
                evaluation_digest: test_digest(2),
                generation: 2,
            },
        );
        assert!(snapshot.verify_against_current(&heads_after).is_err());
    }

    // CAS tests
    #[test]
    fn gate_cas_first_succeeds() {
        let mut store = GateHeadStore::new();
        let r = store.cas("G1".into(), test_digest(1), 0).unwrap();
        assert_eq!(r.generation, 1);
    }

    #[test]
    fn gate_cas_second_succeeds() {
        let mut store = GateHeadStore::new();
        let r1 = store.cas("G1".into(), test_digest(1), 0).unwrap();
        let r2 = store.cas("G1".into(), test_digest(2), 1).unwrap();
        assert_eq!(r2.generation, 2);
        assert_ne!(r1.evaluation_digest, r2.evaluation_digest);
    }

    #[test]
    fn gate_cas_version_conflict() {
        let mut store = GateHeadStore::new();
        store.cas("G1".into(), test_digest(1), 0).unwrap();
        assert!(store.cas("G1".into(), test_digest(2), 0).is_err()); // stale
    }

    #[test]
    fn plan_cas_with_snapshot_succeeds() {
        let mut gate_store = GateHeadStore::new();
        gate_store.cas("G1".into(), test_digest(1), 0).unwrap();
        let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
        let mut plan_store = PlanHeadStore::new();
        let r = plan_store
            .cas(test_digest(10), 0, &snapshot, gate_store.all_heads())
            .unwrap();
        assert_eq!(r.generation, 1);
    }

    #[test]
    fn plan_cas_stale_gate_head_rejected() {
        let mut gate_store = GateHeadStore::new();
        gate_store.cas("G1".into(), test_digest(1), 0).unwrap();
        let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
        // Gate advances after snapshot
        gate_store.cas("G1".into(), test_digest(2), 1).unwrap();
        let mut plan_store = PlanHeadStore::new();
        assert!(
            plan_store
                .cas(test_digest(10), 0, &snapshot, gate_store.all_heads())
                .is_err()
        );
    }

    #[test]
    fn plan_cas_version_conflict() {
        let mut gate_store = GateHeadStore::new();
        gate_store.cas("G1".into(), test_digest(1), 0).unwrap();
        let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
        let mut plan_store = PlanHeadStore::new();
        plan_store
            .cas(test_digest(10), 0, &snapshot, gate_store.all_heads())
            .unwrap();
        assert!(
            plan_store
                .cas(test_digest(11), 0, &snapshot, gate_store.all_heads())
                .is_err()
        );
    }

    #[test]
    fn concurrent_gate_cas_one_winner() {
        let mut store = GateHeadStore::new();
        let r1 = store.cas("G1".into(), test_digest(1), 0);
        let r2 = store.cas("G1".into(), test_digest(2), 0);
        assert!(r1.is_ok() ^ r2.is_ok()); // exactly one winner
    }
