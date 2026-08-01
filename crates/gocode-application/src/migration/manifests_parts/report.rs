impl MigrationReport {
    /// Validate and freeze one migration report.
    pub fn new(fields: MigrationReportFields) -> Result<Self, MigrationError> {
        if fields.source_generation == fields.candidate_generation
            || fields.counts.checked_total().is_none()
            || !all_artifacts_unique([
                &fields.report,
                &fields.source_snapshot,
                &fields.schema,
                &fields.mapping,
                &fields.profile,
            ])
        {
            return Err(MigrationError::StorageContractViolation);
        }
        match (
            &fields.disposition,
            fields.counts.requires_manual_disposition(),
        ) {
            (ImportDisposition::Clean, true) => {}
            (ImportDisposition::ManualAuthorized(authorization), true)
                if authorization.is_valid()
                    && all_artifacts_unique([
                        &fields.report,
                        &fields.source_snapshot,
                        &fields.schema,
                        &fields.mapping,
                        &fields.profile,
                        authorization,
                    ]) => {}
            (ImportDisposition::ManualAuthorized(_), true) => {
                return Err(MigrationError::StorageContractViolation);
            }
            (_, false) => {}
        }
        Ok(Self {
            report: fields.report,
            plan_id: fields.plan_id,
            cycle_id: fields.cycle_id,
            source_snapshot: fields.source_snapshot,
            source_high_water: fields.source_high_water,
            source_generation: fields.source_generation,
            candidate_generation: fields.candidate_generation,
            counts: fields.counts,
            schema: fields.schema,
            mapping: fields.mapping,
            profile: fields.profile,
            integrity: fields.integrity,
            rebuild: fields.rebuild,
            disposition: fields.disposition,
            created_at: fields.created_at,
        })
    }

    /// Return whether risky import classes have explicit manual authorization.
    pub fn is_cutover_eligible(&self) -> bool {
        if self.integrity != ArtifactValidation::Passed
            || self.rebuild != ArtifactValidation::Passed
        {
            return false;
        }
        !self.counts.requires_manual_disposition()
            || matches!(
                self.disposition,
                ImportDisposition::ManualAuthorized(ref authorization)
                    if authorization.is_valid()
            )
    }

    /// Verify the complete report contract after durable decoding.
    pub fn has_valid_identity(&self) -> bool {
        Self::new(MigrationReportFields {
            report: self.report.clone(),
            plan_id: self.plan_id.clone(),
            cycle_id: self.cycle_id.clone(),
            source_snapshot: self.source_snapshot.clone(),
            source_high_water: self.source_high_water,
            source_generation: self.source_generation.clone(),
            candidate_generation: self.candidate_generation.clone(),
            counts: self.counts,
            schema: self.schema.clone(),
            mapping: self.mapping.clone(),
            profile: self.profile.clone(),
            integrity: self.integrity,
            rebuild: self.rebuild,
            disposition: self.disposition.clone(),
            created_at: self.created_at,
        })
        .is_ok()
    }
}
