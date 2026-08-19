impl SqliteMigrationControlStore {
    fn load_plan_impl(
        &self,
        plan_id: &runne_application::migration::types::MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationStoreError> {
        let connection = self.reader()?;
        let row: Option<StoredPlanRow> = connection
            .query_row(
                "SELECT plan_id, cycle_id, cycle_kind, parent_cycle_id,
                        source_generation, candidate_generation, phase, status,
                        routing_unit_digest, gate_policy, plan_version, created_at,
                        plan_blob
                 FROM migration_plans
                 WHERE plan_id = ?1",
                [plan_id.as_str()],
                |row| {
                    Ok(StoredPlanRow {
                        plan_id: row.get(0)?,
                        cycle_id: row.get(1)?,
                        cycle_kind: row.get(2)?,
                        parent_cycle_id: row.get(3)?,
                        source_generation: row.get(4)?,
                        candidate_generation: row.get(5)?,
                        phase: row.get(6)?,
                        status: row.get(7)?,
                        routing_unit_digest: row.get(8)?,
                        gate_policy: row.get(9)?,
                        plan_version: row.get(10)?,
                        created_at: row.get(11)?,
                        plan_blob: row.get(12)?,
                    })
                },
            )
            .optional()
            .map_err(map_read_error)?;
        let Some(stored) = row else {
            return Ok(None);
        };
        let plan = decode_migration_plan(&stored.plan_blob).map_err(map_codec_error)?;
        if !stored.matches(&plan, plan_id)? {
            return Err(MigrationStoreError::CorruptData);
        }

        let mut transition_statement = connection
            .prepare(
                "SELECT transition_id, cycle_id, from_phase, to_phase,
                        plan_version, occurred_at, transition_blob
                 FROM migration_transitions
                 WHERE plan_id = ?1
                 ORDER BY plan_version, transition_id",
            )
            .map_err(map_read_error)?;
        let transition_rows = transition_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut transitions = Vec::new();
        for row in transition_rows {
            let (identity, cycle_id, from, to, version, occurred_at, blob) =
                row.map_err(map_read_error)?;
            let transition = decode_migration_transition(&blob).map_err(map_codec_error)?;
            if transition.plan_id != *plan_id
                || transition.transition_id != identity
                || transition.cycle_id.as_str() != cycle_id
                || i64::from(phase_tag(transition.from)) != from
                || i64::from(phase_tag(transition.to)) != to
                || u64_to_i64(transition.plan_version)? != version
                || transition.occurred_at.as_unix_micros() != occurred_at
            {
                return Err(MigrationStoreError::CorruptData);
            }
            transitions.push(transition);
        }

        let mut evidence_statement = connection
            .prepare(
                "SELECT evidence_digest, evidence_blob
                 FROM migration_evidence
                 WHERE plan_id = ?1
                 ORDER BY recorded_at, evidence_digest",
            )
            .map_err(map_read_error)?;
        let evidence_rows = evidence_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_read_error)?;
        let mut evidence = Vec::new();
        for row in evidence_rows {
            let (stored_digest, blob) = row.map_err(map_read_error)?;
            let computed_digest: [u8; 32] = Sha256::digest(&blob).into();
            if stored_digest != computed_digest {
                return Err(MigrationStoreError::CorruptData);
            }
            evidence.push(decode_migration_evidence(&blob).map_err(map_codec_error)?);
        }

        let mut report_statement = connection
            .prepare(
                "SELECT report_id, cycle_id, report_kind, report_blob, created_at
                 FROM migration_reports
                 WHERE plan_id = ?1
                 ORDER BY created_at, report_id",
            )
            .map_err(map_read_error)?;
        let report_rows = report_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut migration_reports = Vec::new();
        for row in report_rows {
            let (stored_digest, stored_cycle_id, report_kind, blob, created_at) =
                row.map_err(map_read_error)?;
            let report = decode_migration_report(&blob).map_err(map_codec_error)?;
            if report_kind != 1
                || stored_digest != report.report.digest.as_bytes()
                || report.plan_id != *plan_id
                || stored_cycle_id != report.cycle_id.as_str()
                || report.cycle_id != plan.cycle_id
                || report.source_generation != plan.source
                || report.candidate_generation != plan.candidate
                || report.schema.digest != plan.routing_unit.schema_digest
                || report.profile.digest != plan.routing_unit.feature_profile.profile_digest
                || report.created_at.as_unix_micros() != created_at
            {
                return Err(MigrationStoreError::CorruptData);
            }
            migration_reports.push(report);
        }

        let mut manifest_statement = connection
            .prepare(
                "SELECT manifest_id, cycle_id, manifest_blob, created_at
                 FROM cutover_manifests
                 WHERE plan_id = ?1
                 ORDER BY created_at, manifest_id",
            )
            .map_err(map_read_error)?;
        let manifest_rows = manifest_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut cutover_manifests = Vec::new();
        for row in manifest_rows {
            let (stored_digest, stored_cycle_id, blob, created_at) = row.map_err(map_read_error)?;
            let manifest = decode_cutover_manifest(&blob).map_err(map_codec_error)?;
            if stored_digest != manifest.manifest_digest.as_bytes()
                || manifest.plan_id != *plan_id
                || stored_cycle_id != manifest.cycle_id.as_str()
                || manifest.cycle_id != plan.cycle_id
                || manifest.routing_unit != plan.routing_unit
                || manifest.source_generation != plan.source
                || manifest.candidate_generation != plan.candidate
                || created_at != manifest.prepared_at.as_unix_micros()
                || !migration_reports.iter().any(|report| {
                    report.report == manifest.import_report
                        && report.source_high_water == manifest.source_high_water
                        && report.is_cutover_eligible()
                })
            {
                return Err(MigrationStoreError::CorruptData);
            }
            cutover_manifests.push(manifest);
        }

        let mut rollback_statement = connection
            .prepare(
                "SELECT manifest_id, cycle_id, parent_plan_id, manifest_blob, created_at
                 FROM rollback_manifests
                 WHERE plan_id = ?1
                 ORDER BY created_at, manifest_id",
            )
            .map_err(map_read_error)?;
        let rollback_rows = rollback_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut rollback_manifests = Vec::new();
        for row in rollback_rows {
            let (stored_digest, stored_cycle_id, parent_plan_id, blob, created_at) =
                row.map_err(map_read_error)?;
            let manifest = decode_rollback_manifest(&blob).map_err(map_codec_error)?;
            if stored_digest != manifest.manifest.digest.as_bytes()
                || manifest.plan_id != *plan_id
                || stored_cycle_id != manifest.cycle_id.as_str()
                || parent_plan_id != manifest.parent_plan_id.as_str()
                || created_at != manifest.created_at.as_unix_micros()
            {
                return Err(MigrationStoreError::CorruptData);
            }
            rollback_manifests.push(manifest);
        }

        let mut retirement_statement = connection
            .prepare(
                "SELECT manifest_id, cycle_id, manifest_blob, created_at
                 FROM retirement_manifests
                 WHERE plan_id = ?1
                 ORDER BY created_at, manifest_id",
            )
            .map_err(map_read_error)?;
        let retirement_rows = retirement_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut retirement_manifests = Vec::new();
        for row in retirement_rows {
            let (stored_digest, stored_cycle_id, blob, created_at) = row.map_err(map_read_error)?;
            let manifest = decode_retirement_manifest(&blob).map_err(map_codec_error)?;
            if stored_digest != manifest.manifest.digest.as_bytes()
                || manifest.plan_id != *plan_id
                || stored_cycle_id != manifest.cycle_id.as_str()
                || created_at != manifest.created_at.as_unix_micros()
            {
                return Err(MigrationStoreError::CorruptData);
            }
            retirement_manifests.push(manifest);
        }

        Ok(Some(LoadedMigrationPlan {
            plan,
            transitions,
            evidence,
            migration_reports,
            cutover_manifests,
            rollback_manifests,
            retirement_manifests,
        }))
    }
}
