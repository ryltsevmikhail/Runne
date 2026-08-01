#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingUnit {
    pub deployment: DeploymentId,
    pub cohort: CohortSelector,
    pub feature_profile: FeatureProfileRef,
    pub contract_digest: ArtifactDigest,
    pub schema_digest: ArtifactDigest,
    pub config_digest: ArtifactDigest,
}

impl RoutingUnit {
    pub fn digest(&self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(ROUTING_UNIT_DOMAIN_PREFIX);
        update_length_prefixed(&mut hasher, self.deployment.as_str());
        hasher.update((self.cohort.dimensions().len() as u16).to_be_bytes());
        for dimension in self.cohort.dimensions() {
            update_length_prefixed(&mut hasher, dimension.key());
            update_length_prefixed(&mut hasher, dimension.value());
        }
        update_length_prefixed(&mut hasher, &self.feature_profile.profile_id);
        hasher.update(self.feature_profile.profile_revision.to_be_bytes());
        hasher.update(self.feature_profile.profile_digest.as_bytes());
        hasher.update(self.contract_digest.as_bytes());
        hasher.update(self.schema_digest.as_bytes());
        hasher.update(self.config_digest.as_bytes());
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingSnapshot {
    pub routing_generation: RoutingGeneration,
    pub source: RuntimeGenerationRef,
    pub candidate: RuntimeGenerationRef,
    pub cohort: CohortSelector,
    pub authority: RuntimeAuthority,
    pub contract_digest: ArtifactDigest,
    pub profile_digest: ArtifactDigest,
    pub config_digest: ArtifactDigest,
    pub fencing_token: FencingToken,
    pub rollback_disposition: RollbackDisposition,
    pub committed_at: Timestamp,
}

impl RoutingSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        routing_generation: RoutingGeneration,
        source: RuntimeGenerationRef,
        candidate: RuntimeGenerationRef,
        phase: MigrationPhase,
        authority: RuntimeAuthority,
        routing_unit: RoutingUnit,
        fencing_token: FencingToken,
        rollback_disposition: RollbackDisposition,
        committed_at: Timestamp,
    ) -> Result<Self, MigrationValueError> {
        if source == candidate {
            return Err(MigrationValueError::SourceAndCandidateMustDiffer);
        }
        match &authority {
            RuntimeAuthority::Source(generation) if generation != &source => {
                return Err(MigrationValueError::AuthorityGenerationMismatch);
            }
            RuntimeAuthority::Candidate(generation) if generation != &candidate => {
                return Err(MigrationValueError::AuthorityGenerationMismatch);
            }
            RuntimeAuthority::Candidate(_)
                if matches!(
                    phase,
                    MigrationPhase::Baseline
                        | MigrationPhase::Foundation
                        | MigrationPhase::ReadOnlyParity
                        | MigrationPhase::SimulatedShadow
                ) =>
            {
                return Err(MigrationValueError::CandidateAuthorityBeforeCanary);
            }
            _ => {}
        }
        if fencing_token.as_bytes() == &[0; 32] {
            return Err(MigrationValueError::ZeroFencingToken);
        }

        Ok(Self {
            routing_generation,
            source,
            candidate,
            cohort: routing_unit.cohort,
            authority,
            contract_digest: routing_unit.contract_digest,
            profile_digest: routing_unit.feature_profile.profile_digest,
            config_digest: routing_unit.config_digest,
            fencing_token,
            rollback_disposition,
            committed_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBinding {
    pub aggregate_id: AggregateId,
    pub authority: RuntimeAuthority,
    pub runtime_generation: RuntimeGenerationRef,
    pub routing_generation: RoutingGeneration,
    pub fencing_token: FencingToken,
    pub bound_at: Timestamp,
}

impl RuntimeBinding {
    pub fn new(
        aggregate_id: AggregateId,
        authority: RuntimeAuthority,
        runtime_generation: RuntimeGenerationRef,
        routing_generation: RoutingGeneration,
        fencing_token: FencingToken,
        bound_at: Timestamp,
    ) -> Result<Self, MigrationValueError> {
        if authority.generation() != &runtime_generation {
            return Err(MigrationValueError::BindingAuthorityGenerationMismatch);
        }
        if fencing_token.as_bytes() == &[0; 32] {
            return Err(MigrationValueError::ZeroFencingToken);
        }

        Ok(Self {
            aggregate_id,
            authority,
            runtime_generation,
            routing_generation,
            fencing_token,
            bound_at,
        })
    }
}
