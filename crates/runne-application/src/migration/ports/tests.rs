#[cfg(test)]
mod tests {
    use runne_domain::{
        id::{CommandId, IdempotencyKey},
        timestamp::Timestamp,
    };

    use super::*;
    use crate::migration::{
        state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
        types::{
            ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
            FencingToken, GatePolicyRef, MigrationCycleId, MigrationPlanId, OperatorId,
            RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit, RuntimeAuthority,
            RuntimeGenerationRef,
        },
    };

    #[test]
    fn production_mutation_requires_an_expected_routing_generation() {
        let commit = MigrationCommit::new(
            test_context(None),
            test_fingerprint(),
            test_plan(),
            vec![
                MigrationMutation::AppendTransition(test_transition()),
                MigrationMutation::AppendRoutingSnapshot(candidate_snapshot()),
            ],
            test_outcome(),
            Some(test_audit_record()),
        );

        assert_eq!(
            commit,
            Err(crate::migration::error::MigrationError::ExpectedRoutingGenerationRequired)
        );
    }

    #[test]
    fn audit_record_is_required_for_every_mutation() {
        let commit = MigrationCommit::new(
            test_context(Some(RoutingGeneration::new(1).unwrap())),
            test_fingerprint(),
            test_plan(),
            vec![MigrationMutation::AppendTransition(test_transition())],
            test_outcome(),
            None,
        );

        assert_eq!(
            commit,
            Err(crate::migration::error::MigrationError::AuditUnavailable)
        );
    }

    #[test]
    fn duplicate_mutation_identity_is_rejected_before_the_adapter() {
        let transition = test_transition();
        let commit = MigrationCommit::new(
            test_context(Some(RoutingGeneration::new(1).unwrap())),
            test_fingerprint(),
            test_plan(),
            vec![
                MigrationMutation::AppendTransition(transition.clone()),
                MigrationMutation::AppendTransition(transition),
            ],
            test_outcome(),
            Some(test_audit_record()),
        );

        assert_eq!(
            commit,
            Err(crate::migration::error::MigrationError::StorageContractViolation)
        );
    }

    #[test]
    fn audit_identity_must_match_the_command_and_plan() {
        let mut audit = test_audit_record();
        audit.command_id = "018f2e3a-8d5c-7b20-8d9a-000000000002"
            .parse::<CommandId>()
            .unwrap();
        let commit = MigrationCommit::new(
            test_context(Some(RoutingGeneration::new(1).unwrap())),
            test_fingerprint(),
            test_plan(),
            vec![MigrationMutation::AppendTransition(test_transition())],
            test_outcome(),
            Some(audit),
        );

        assert_eq!(
            commit,
            Err(crate::migration::error::MigrationError::StorageContractViolation)
        );
    }

    fn test_context(
        expected_routing_generation: Option<RoutingGeneration>,
    ) -> MigrationCommandContext {
        MigrationCommandContext {
            command_id: "018f2e3a-8d5c-7b20-8d9a-000000000001"
                .parse::<CommandId>()
                .unwrap(),
            idempotency_key: IdempotencyKey::new("migration-command-1").unwrap(),
            operator_id: OperatorId::new("operator-1").unwrap(),
            expected_plan_version: 0,
            expected_routing_generation,
            evaluated_at: Timestamp::from_unix_micros(100),
        }
    }

    fn test_plan() -> MigrationPlan {
        MigrationPlan {
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            cycle_kind: MigrationCycleKind::Forward,
            source: source_generation(),
            candidate: candidate_generation(),
            phase: MigrationPhase::InternalCanary,
            status: MigrationPlanStatus::Active,
            routing_unit: test_routing_unit(),
            gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
            plan_version: 0,
            created_at: Timestamp::from_unix_micros(1),
        }
    }

    fn test_transition() -> MigrationTransition {
        MigrationTransition {
            transition_id: "transition-1".to_owned(),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            from: MigrationPhase::SimulatedShadow,
            to: MigrationPhase::InternalCanary,
            plan_version: 1,
            occurred_at: Timestamp::from_unix_micros(10),
        }
    }

    fn candidate_snapshot() -> RoutingSnapshot {
        RoutingSnapshot::new(
            RoutingGeneration::new(2).unwrap(),
            source_generation(),
            candidate_generation(),
            MigrationPhase::InternalCanary,
            RuntimeAuthority::Candidate(candidate_generation()),
            test_routing_unit(),
            FencingToken::new([7; 32]).unwrap(),
            RollbackDisposition::Eligible,
            Timestamp::from_unix_micros(10),
        )
        .unwrap()
    }

    fn test_audit_record() -> MigrationAuditRecord {
        MigrationAuditRecord {
            record_id: ArtifactDigest::from_bytes([9; 32]),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            command_id: test_context(None).command_id,
            operator_id: OperatorId::new("operator-1").unwrap(),
            action: MigrationAuditAction::AdvancePhase,
            recorded_at: Timestamp::from_unix_micros(10),
        }
    }

    fn test_fingerprint() -> MigrationCommandFingerprint {
        MigrationCommandFingerprint::from_bytes([8; 32])
    }

    fn test_outcome() -> MigrationCommandOutcome {
        MigrationCommandOutcome {
            plan: test_plan(),
            routing_snapshot: Some(candidate_snapshot()),
            transition_id: "transition-1".to_owned(),
        }
    }

    fn source_generation() -> RuntimeGenerationRef {
        RuntimeGenerationRef::new("runtime-legacy").unwrap()
    }

    fn candidate_generation() -> RuntimeGenerationRef {
        RuntimeGenerationRef::new("runtime-native").unwrap()
    }

    fn test_routing_unit() -> RoutingUnit {
        RoutingUnit {
            deployment: DeploymentId::new("production").unwrap(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
            ])
            .unwrap(),
            feature_profile: FeatureProfileRef::new(
                "default",
                1,
                ArtifactDigest::from_bytes([1; 32]),
            )
            .unwrap(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            schema_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
        }
    }
}
