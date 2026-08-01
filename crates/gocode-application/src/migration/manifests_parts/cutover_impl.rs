impl CutoverManifest {
    /// Validate all evidence and freeze a complete cutover manifest.
    pub fn new(fields: CutoverManifestFields) -> Result<Self, MigrationError> {
        if !fields.migration_report.has_valid_identity() {
            return Err(MigrationError::StorageContractViolation);
        }
        if !fields.migration_report.is_cutover_eligible() {
            return Err(MigrationError::ImportAmbiguous);
        }
        if !fields.drain_report.complete {
            return Err(MigrationError::DrainIncomplete);
        }
        if fields.drain_report.timed_out {
            return Err(MigrationError::DrainTimedOut);
        }
        if fields.drain_report.unresolved_effects != 0 {
            return Err(MigrationError::UnresolvedEffect);
        }
        if fields.candidate_validation.validation != ArtifactValidation::Passed {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        if fields.intent == CutoverIntent::CohortExpansion
            && fields.rollback_policy == RollbackPolicy::ManualOnly
        {
            return Err(MigrationError::RollbackIneligible);
        }
        fields.rollout_policy.validate_manifest(
            fields.intent,
            &fields.routing_unit,
            fields.expected_routing_generation,
            fields.prepared_at,
        )?;
        let expected_prepared_version = fields
            .expected_plan_version
            .checked_add(1)
            .ok_or(MigrationError::ArithmeticOverflow)?;
        if fields.plan_id != fields.migration_report.plan_id
            || fields.cycle_id != fields.migration_report.cycle_id
            || fields.source_generation != fields.migration_report.source_generation
            || fields.candidate_generation != fields.migration_report.candidate_generation
            || fields.source_high_water() != fields.drain_report.source_high_water
            || fields.expected_routing_generation != fields.routing_generation_at_prepare
            || fields.prepared_plan_version != expected_prepared_version
            || fields.routing_unit.schema_digest != fields.migration_report.schema.digest
            || fields.routing_unit.feature_profile.profile_digest
                != fields.migration_report.profile.digest
        {
            return Err(MigrationError::StorageContractViolation);
        }
        let rollback_contract = match &fields.rollback_policy {
            RollbackPolicy::ReverseMigrationRequired(contract) => Some(contract),
            RollbackPolicy::BeforeCandidateWrites | RollbackPolicy::ManualOnly => None,
        };
        let mut artifacts = vec![
            &fields.manifest,
            &fields.source_release,
            &fields.candidate_release,
            &fields.frozen_evidence_set,
            &fields.migration_report.report,
            &fields.drain_report.report,
            &fields.candidate_validation.report,
            &fields.operator_authorization,
        ];
        if let Some(contract) = rollback_contract {
            artifacts.push(contract);
        }
        if !all_artifacts_unique(artifacts)
            || !valid_bounded(&fields.prepared_transition_id, MAX_TRANSITION_ID_BYTES)
        {
            return Err(MigrationError::StorageContractViolation);
        }

        Ok(Self {
            manifest_digest: fields.manifest.digest,
            manifest_ref: fields.manifest.reference,
            plan_id: fields.plan_id,
            cycle_id: fields.cycle_id,
            intent: fields.intent,
            rollout_policy: fields.rollout_policy,
            routing_unit: fields.routing_unit,
            source_release: fields.source_release,
            source_generation: fields.source_generation,
            candidate_release: fields.candidate_release,
            candidate_generation: fields.candidate_generation,
            evidence_set_digest: fields.frozen_evidence_set.digest,
            evidence_set_ref: fields.frozen_evidence_set.reference,
            import_report: fields.migration_report.report,
            drain_report: fields.drain_report.report,
            candidate_validation: fields.candidate_validation.report,
            source_high_water: fields.migration_report.source_high_water,
            expected_routing_generation: fields.expected_routing_generation,
            rollback_policy: fields.rollback_policy,
            retention_until: fields.retention_until,
            operator_authorization: fields.operator_authorization,
            prepared_transition_id: fields.prepared_transition_id,
            expected_plan_version: fields.expected_plan_version,
            plan_version: fields.prepared_plan_version,
            prepared_at: fields.prepared_at,
        })
    }

    /// Verify persisted identity and all immutable artifact references.
    pub fn has_valid_identity(&self) -> bool {
        let rollback_contract = match &self.rollback_policy {
            RollbackPolicy::ReverseMigrationRequired(contract) => Some(contract),
            RollbackPolicy::BeforeCandidateWrites | RollbackPolicy::ManualOnly => None,
        };
        let mut artifacts = vec![
            ArtifactRef {
                reference: self.manifest_ref.clone(),
                digest: self.manifest_digest,
            },
            self.source_release.clone(),
            self.candidate_release.clone(),
            ArtifactRef {
                reference: self.evidence_set_ref.clone(),
                digest: self.evidence_set_digest,
            },
            self.import_report.clone(),
            self.drain_report.clone(),
            self.candidate_validation.clone(),
            self.operator_authorization.clone(),
        ];
        if let Some(contract) = rollback_contract {
            artifacts.push(contract.clone());
        }
        all_artifacts_unique(artifacts.iter())
            && valid_bounded(&self.prepared_transition_id, MAX_TRANSITION_ID_BYTES)
            && self.expected_plan_version.checked_add(1) == Some(self.plan_version)
            && self.source_generation != self.candidate_generation
            && self.retention_until >= self.prepared_at
            && !(self.intent == CutoverIntent::CohortExpansion
                && self.rollback_policy == RollbackPolicy::ManualOnly)
            && self
                .rollout_policy
                .validate_manifest(
                    self.intent,
                    &self.routing_unit,
                    self.expected_routing_generation,
                    self.prepared_at,
                )
                .is_ok()
    }
}
