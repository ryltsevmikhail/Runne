    use super::*;
    use crate::migration::types::CohortDimension;

    #[test]
    fn stale_revoked_and_scope_mismatched_evidence_never_applies() {
        let context = gate_context_at(200);

        let mut expired = passed_evidence();
        expired.valid_until = Timestamp::from_unix_micros(200);
        assert_eq!(
            expired.applies_to(&context),
            Err(GateApplicabilityError::Expired)
        );

        let mut revoked = passed_evidence();
        revoked.status = GateStatus::Revoked {
            reason: GateRevocationReason::SecurityRevoked,
        };
        assert_eq!(
            revoked.applies_to(&context),
            Err(GateApplicabilityError::Revoked)
        );

        let mut wrong_candidate = passed_evidence();
        wrong_candidate.candidate_generation =
            RuntimeGenerationRef::new("candidate-other").unwrap();
        assert_eq!(
            wrong_candidate.applies_to(&context),
            Err(GateApplicabilityError::CandidateGenerationMismatch)
        );
    }

    #[test]
    fn all_ten_families_have_stable_discriminants() {
        assert_eq!(
            GateFamily::ALL,
            [
                GateFamily::StoreIntegrity,
                GateFamily::CanonicalAudit,
                GateFamily::SecurityPolicy,
                GateFamily::PlatformCertification,
                GateFamily::RuntimeHealth,
                GateFamily::RecoveryReadiness,
                GateFamily::DrainReadiness,
                GateFamily::RollbackReadiness,
                GateFamily::CapacitySlo,
                GateFamily::ShadowIsolation,
            ]
        );
    }

    #[test]
    fn production_phases_use_distinct_policy_revisions_with_all_critical_families() {
        let canary = PhaseGatePolicy::for_target(MigrationPhase::InternalCanary).unwrap();
        let cohort = PhaseGatePolicy::for_target(MigrationPhase::CohortRollout).unwrap();
        let default_native = PhaseGatePolicy::for_target(MigrationPhase::DefaultNative).unwrap();

        assert_eq!(canary.revision(), 1);
        assert_eq!(cohort.revision(), 2);
        assert_eq!(default_native.revision(), 3);
        assert_eq!(cohort.required(), PHASE_4);
        assert_eq!(default_native.required(), PHASE_4);
    }

    #[test]
    fn applicability_requires_a_passed_fresh_exact_nonempty_scope() {
        let context = gate_context_at(200);
        assert_eq!(passed_evidence().applies_to(&context), Ok(()));

        let mut evidence = passed_evidence();
        evidence.measured_at = Timestamp::from_unix_micros(201);
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::NotYetValid)
        );

        let mut evidence = passed_evidence();
        evidence.status = GateStatus::Failed {
            code: GateFailureCode::Integrity,
        };
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::Failed)
        );

        let mut evidence = passed_evidence();
        evidence.source_generation = RuntimeGenerationRef::new("source-other").unwrap();
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::SourceGenerationMismatch)
        );

        let mut evidence = passed_evidence();
        evidence.cohort = CohortSelector::new(vec![
            CohortDimension::new("project_class", "external").unwrap(),
        ])
        .unwrap();
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::CohortMismatch)
        );

        let mismatched_digests = [
            (
                ArtifactDigest::from_bytes([12; 32]),
                context.profile_digest,
                context.config_digest,
                GateApplicabilityError::ContractDigestMismatch,
            ),
            (
                context.contract_digest,
                ArtifactDigest::from_bytes([13; 32]),
                context.config_digest,
                GateApplicabilityError::ProfileDigestMismatch,
            ),
            (
                context.contract_digest,
                context.profile_digest,
                ArtifactDigest::from_bytes([14; 32]),
                GateApplicabilityError::ConfigDigestMismatch,
            ),
        ];
        for (contract, profile, config, expected) in mismatched_digests {
            let mut evidence = passed_evidence();
            evidence.contract_digest = contract;
            evidence.profile_digest = profile;
            evidence.config_digest = config;
            assert_eq!(evidence.applies_to(&context), Err(expected));
        }

        let mut evidence = passed_evidence();
        evidence.evidence_digest = ArtifactDigest::from_bytes([0; 32]);
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::EmptyEvidenceDigest)
        );
    }

    fn gate_context_at(now: i64) -> GateContext {
        GateContext {
            source_generation: RuntimeGenerationRef::new("source-v1").unwrap(),
            candidate_generation: RuntimeGenerationRef::new("candidate-v1").unwrap(),
            cohort: cohort(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            profile_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
            now: Timestamp::from_unix_micros(now),
        }
    }

    fn passed_evidence() -> GateEvidence {
        GateEvidence {
            gate_id: GateId::new("gate-1").unwrap(),
            gate_revision: 1,
            family: GateFamily::StoreIntegrity,
            source_generation: RuntimeGenerationRef::new("source-v1").unwrap(),
            candidate_generation: RuntimeGenerationRef::new("candidate-v1").unwrap(),
            cohort: cohort(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            profile_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
            measured_at: Timestamp::from_unix_micros(100),
            valid_until: Timestamp::from_unix_micros(300),
            status: GateStatus::Passed,
            evidence_digest: ArtifactDigest::from_bytes([5; 32]),
        }
    }

    fn cohort() -> CohortSelector {
        CohortSelector::new(vec![
            CohortDimension::new("project_class", "internal").unwrap(),
        ])
        .unwrap()
    }
