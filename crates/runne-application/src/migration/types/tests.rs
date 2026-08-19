#[cfg(test)]
mod tests {
    use runne_domain::{
        id::{AggregateId, TaskRunId},
        timestamp::Timestamp,
    };

    use super::*;

    #[test]
    fn identities_reject_empty_control_and_oversized_values() {
        assert!(MigrationPlanId::new("").is_err());
        assert!(MigrationPlanId::new("bad\nplan").is_err());
        assert!(MigrationPlanId::new("x".repeat(MAX_MIGRATION_ID_BYTES + 1)).is_err());
    }

    #[test]
    fn routing_unit_digest_is_canonical_and_domain_separated() {
        let unit = test_routing_unit();
        assert_eq!(
            unit.digest().to_string(),
            "sha256:66986864a81189afb425e38a8cef3f3aa09f3efc094c517b94771d294b91a478"
        );
    }

    #[test]
    fn routing_unit_digest_changes_with_profile_digest() {
        let unit = test_routing_unit();
        let mut changed = unit.clone();
        changed.feature_profile.profile_digest = ArtifactDigest::from_bytes([9; 32]);

        assert_ne!(unit.digest(), changed.digest());
    }

    #[test]
    fn cohort_selector_rejects_untrusted_dimensions() {
        assert!(
            CohortSelector::new(vec![
                CohortDimension::new("taskrun_id", "018f2e3a").unwrap()
            ])
            .is_err()
        );
    }

    #[test]
    fn source_only_snapshot_rejects_candidate_authority_before_canary() {
        let result = RoutingSnapshot::new(
            RoutingGeneration::new(1).unwrap(),
            source_generation(),
            candidate_generation(),
            MigrationPhase::SimulatedShadow,
            RuntimeAuthority::Candidate(candidate_generation()),
            test_routing_unit(),
            FencingToken::from_bytes([7; 32]),
            RollbackDisposition::Eligible,
            Timestamp::from_unix_micros(10),
        );

        assert_eq!(
            result,
            Err(MigrationValueError::CandidateAuthorityBeforeCanary)
        );
    }

    #[test]
    fn runtime_binding_rejects_authority_generation_mismatch() {
        assert_eq!(
            RuntimeBinding::new(
                aggregate_id(),
                RuntimeAuthority::Source(source_generation()),
                candidate_generation(),
                RoutingGeneration::new(1).unwrap(),
                FencingToken::from_bytes([7; 32]),
                Timestamp::from_unix_micros(10),
            ),
            Err(MigrationValueError::BindingAuthorityGenerationMismatch)
        );
    }

    #[test]
    fn routing_snapshot_rejects_invalid_authority_and_token() {
        let routing_generation = RoutingGeneration::new(1).unwrap();
        let source = source_generation();
        let candidate = candidate_generation();

        assert_eq!(
            RoutingSnapshot::new(
                routing_generation,
                source.clone(),
                source.clone(),
                MigrationPhase::InternalCanary,
                RuntimeAuthority::Source(source.clone()),
                test_routing_unit(),
                FencingToken::from_bytes([7; 32]),
                RollbackDisposition::Eligible,
                Timestamp::from_unix_micros(10),
            ),
            Err(MigrationValueError::SourceAndCandidateMustDiffer)
        );
        assert_eq!(
            RoutingSnapshot::new(
                routing_generation,
                source.clone(),
                candidate.clone(),
                MigrationPhase::InternalCanary,
                RuntimeAuthority::Source(candidate),
                test_routing_unit(),
                FencingToken::from_bytes([7; 32]),
                RollbackDisposition::Eligible,
                Timestamp::from_unix_micros(10),
            ),
            Err(MigrationValueError::AuthorityGenerationMismatch)
        );
        assert_eq!(
            RoutingSnapshot::new(
                routing_generation,
                source,
                candidate_generation(),
                MigrationPhase::InternalCanary,
                RuntimeAuthority::Source(source_generation()),
                test_routing_unit(),
                FencingToken::from_bytes([0; 32]),
                RollbackDisposition::Eligible,
                Timestamp::from_unix_micros(10),
            ),
            Err(MigrationValueError::ZeroFencingToken)
        );
    }

    #[test]
    fn routing_snapshot_copies_routing_unit_scope_and_digests() {
        let routing_unit = test_routing_unit();
        let snapshot = RoutingSnapshot::new(
            RoutingGeneration::new(1).unwrap(),
            source_generation(),
            candidate_generation(),
            MigrationPhase::InternalCanary,
            RuntimeAuthority::Candidate(candidate_generation()),
            routing_unit.clone(),
            FencingToken::from_bytes([7; 32]),
            RollbackDisposition::Eligible,
            Timestamp::from_unix_micros(10),
        )
        .unwrap();

        assert_eq!(snapshot.cohort, routing_unit.cohort);
        assert_eq!(snapshot.contract_digest, routing_unit.contract_digest);
        assert_eq!(
            snapshot.profile_digest,
            routing_unit.feature_profile.profile_digest
        );
        assert_eq!(snapshot.config_digest, routing_unit.config_digest);
    }

    fn source_generation() -> RuntimeGenerationRef {
        RuntimeGenerationRef::new("runtime-legacy").unwrap()
    }

    fn candidate_generation() -> RuntimeGenerationRef {
        RuntimeGenerationRef::new("runtime-native").unwrap()
    }

    fn aggregate_id() -> AggregateId {
        AggregateId::TaskRun(
            "018f2e3a-8d5c-7b20-8d9a-000000000001"
                .parse::<TaskRunId>()
                .unwrap(),
        )
    }

    fn test_routing_unit() -> RoutingUnit {
        RoutingUnit {
            deployment: DeploymentId::new("production").unwrap(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
                CohortDimension::new("deployment_mode", "public").unwrap(),
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
