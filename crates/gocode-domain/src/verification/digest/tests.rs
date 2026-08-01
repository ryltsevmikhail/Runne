    use super::*;
    use uuid::Uuid;

    #[test]
    fn digest_from_valid_hex() {
        let hex = "a".repeat(64);
        let d = VerificationDigest::from_hex(&hex).unwrap();
        assert_eq!(d.to_hex(), hex);
    }

    #[test]
    fn digest_from_invalid_hex_rejects() {
        assert!(VerificationDigest::from_hex("gg".repeat(32).as_str()).is_err());
    }

    #[test]
    fn digest_from_wrong_length_rejects() {
        assert!(VerificationDigest::from_hex("abc").is_err());
    }

    #[test]
    fn digest_from_uppercase_rejects() {
        assert!(VerificationDigest::from_hex("A".repeat(64).as_str()).is_err());
    }

    #[test]
    fn evidence_set_digest_is_deterministic() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();
        let d1 = VerificationDigest::from_bytes([1u8; 32]);
        let d2 = VerificationDigest::from_bytes([2u8; 32]);

        let refs = vec![(id1, d1.clone()), (id2, d2.clone())];
        let result1 = contract.compute_evidence_set(&refs).unwrap();
        let result2 = contract.compute_evidence_set(&refs).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn evidence_set_digest_changes_with_content() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let id1 = Uuid::now_v7();
        let refs1 = vec![(id1, VerificationDigest::from_bytes([1u8; 32]))];
        let refs2 = vec![(id1, VerificationDigest::from_bytes([2u8; 32]))];

        let r1 = contract.compute_evidence_set(&refs1).unwrap();
        let r2 = contract.compute_evidence_set(&refs2).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn evidence_set_digest_same_for_different_order() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();
        let d1 = VerificationDigest::from_bytes([1u8; 32]);
        let d2 = VerificationDigest::from_bytes([2u8; 32]);

        let refs1 = vec![(id1, d1.clone()), (id2, d2.clone())];
        let refs2 = vec![(id2, d2.clone()), (id1, d1.clone())];
        assert_eq!(
            contract.compute_evidence_set(&refs1).unwrap(),
            contract.compute_evidence_set(&refs2).unwrap()
        );
    }

    #[test]
    fn duplicate_evidence_ref_rejected() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let id = Uuid::now_v7();
        let d = VerificationDigest::from_bytes([1u8; 32]);
        let refs = vec![(id, d.clone()), (id, d.clone())];
        assert!(contract.compute_evidence_set(&refs).is_err());
    }

    #[test]
    fn empty_evidence_set_has_digest() {
        let contract = DigestContract::new("gocode:evidence-set:v1");
        let refs: Vec<(Uuid, VerificationDigest)> = vec![];
        let result = contract.compute_evidence_set(&refs).unwrap();
        // Non-zero digest even for empty set
        assert!(!result.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn domain_tag_separation() {
        let c1 = DigestContract::new("gocode:evidence-set:v1");
        let c2 = DigestContract::new("gocode:evidence-set:v2");
        let id = Uuid::now_v7();
        let d = VerificationDigest::from_bytes([1u8; 32]);
        let refs = vec![(id, d)];
        assert_ne!(
            c1.compute_evidence_set(&refs).unwrap(),
            c2.compute_evidence_set(&refs).unwrap()
        );
    }

    #[test]
    fn gate_evaluation_digest_formula() {
        let contract = DigestContract::new("gocode:gate-evaluation:v1");
        let input = GateEvaluationInput {
            definition_digest: &VerificationDigest::from_bytes([1u8; 32]),
            run_id_bytes: &[2u8; 16],
            profile_digest: &VerificationDigest::from_bytes([3u8; 32]),
            policy_revision: "v1",
            evidence_set_digest: &VerificationDigest::from_bytes([4u8; 32]),
            result: "passed",
            reason: "all criteria met",
            predecessor_ref_bytes: &[],
            head_generation: 1,
        };
        let result = contract.compute_gate_evaluation(&input);
        assert!(!result.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn plan_evaluation_digest_formula() {
        let contract = DigestContract::new("gocode:plan-evaluation:v1");
        let input = PlanEvaluationInput {
            run_id_bytes: &[1u8; 16],
            profile_digest: &VerificationDigest::from_bytes([2u8; 32]),
            plan_binding_bytes: b"plan-binding",
            gate_refs_canonical_bytes: b"gate-refs",
            gate_head_snapshot_digest: &VerificationDigest::from_bytes([3u8; 32]),
            policy_revision: "v1",
            result: "passed",
            reason: "all gates passed",
            predecessor_ref_bytes: &[],
            head_generation: 1,
        };
        let result = contract.compute_plan_evaluation(&input);
        assert!(!result.as_bytes().iter().all(|b| *b == 0));
    }
