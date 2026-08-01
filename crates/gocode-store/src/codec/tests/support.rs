    const TR_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
    const ATT_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
    const CONV_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
    const WS_ID: &str = "018f2e3a-7000-7000-8000-000000000004";

    fn phase5_context_ref() -> ContextManifestRef {
        ContextManifestRef {
            manifest_id: TR_ID.parse().unwrap(),
            taskrun_id: TR_ID.parse().unwrap(),
            attempt_id: ATT_ID.parse().unwrap(),
            cycle_id: CONV_ID.parse().unwrap(),
            revision: 1,
            policy_revision: "context-v1".into(),
            integrity_digest: IntegrityDigest::from_bytes([1; 32]),
        }
    }

    fn phase5_budget_ref() -> BudgetReservationRef {
        BudgetReservationRef {
            reservation_id: WS_ID.parse().unwrap(),
            taskrun_id: TR_ID.parse().unwrap(),
            attempt_id: ATT_ID.parse().unwrap(),
            retry_ordinal: 1,
            reservation_digest: IntegrityDigest::from_bytes([2; 32]),
        }
    }

    fn phase5_plan_ref() -> PlanRevisionRef {
        PlanRevisionRef {
            plan_id: WS_ID.parse().unwrap(),
            taskrun_id: TR_ID.parse().unwrap(),
            cycle_id: CONV_ID.parse().unwrap(),
            revision: 2,
            context_manifest_ref: phase5_context_ref(),
            expected_proposal_indexes: vec![0],
            proposal_batch_digest: IntegrityDigest::from_bytes([3; 32]),
            planning_policy_ref: ResultRef::new(
                TR_ID.parse().unwrap(),
                "application/json",
                IntegrityDigest::from_bytes([4; 32]),
            )
            .unwrap(),
            planning_budget_ref: phase5_budget_ref(),
            parent_ref: Some(PlanParentRef {
                plan_id: WS_ID.parse().unwrap(),
                revision: 1,
                integrity_digest: IntegrityDigest::from_bytes([5; 32]),
            }),
            integrity_digest: IntegrityDigest::from_bytes([6; 32]),
        }
    }

    fn phase5_step_ref() -> StepOutcomeRef {
        StepOutcomeRef {
            cycle_id: CONV_ID.parse().unwrap(),
            proposal_index: 0,
            step_id: WS_ID.parse().unwrap(),
            outcome_digest: IntegrityDigest::from_bytes([7; 32]),
        }
    }

    // ── TaskRunEvent round-trip ────────────────────────────────────────
