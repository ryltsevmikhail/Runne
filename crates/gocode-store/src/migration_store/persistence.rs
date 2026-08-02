fn persist_mutations(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let unit_digest = commit.plan().routing_unit.digest();
    let advances_head = commit
        .mutations()
        .iter()
        .any(|mutation| matches!(mutation, MigrationMutation::AdvanceRoutingHead { .. }));
    for mutation in commit.mutations() {
        match mutation {
            MigrationMutation::InsertPlan(plan) => insert_plan(transaction, plan)?,
            MigrationMutation::AppendTransition(transition) => {
                let blob = encode_migration_transition(transition).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO migration_transitions
                         (transition_id, plan_id, cycle_id, from_phase, to_phase,
                          plan_version, occurred_at, transition_blob)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            transition.transition_id,
                            transition.plan_id.as_str(),
                            transition.cycle_id.as_str(),
                            phase_tag(transition.from),
                            phase_tag(transition.to),
                            u64_to_i64(transition.plan_version)?,
                            transition.occurred_at.as_unix_micros(),
                            blob,
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendEvidence(evidence) => {
                let blob = encode_migration_evidence(evidence).map_err(map_codec_error)?;
                let digest: [u8; 32] = Sha256::digest(&blob).into();
                transaction
                    .execute(
                        "INSERT INTO migration_evidence
                         (evidence_digest, plan_id, evidence_blob, recorded_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            digest.as_slice(),
                            commit.plan().plan_id.as_str(),
                            blob,
                            commit.audit().recorded_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendMigrationReport(report) => {
                let blob = encode_migration_report(report).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO migration_reports
                         (report_id, plan_id, cycle_id, report_kind, report_blob, created_at)
                         VALUES (?1, ?2, ?3, 1, ?4, ?5)",
                        params![
                            report.report.digest.as_bytes().as_slice(),
                            report.plan_id.as_str(),
                            report.cycle_id.as_str(),
                            blob,
                            report.created_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendCutoverManifest(manifest) => {
                let blob = encode_cutover_manifest(manifest).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO cutover_manifests
                         (manifest_id, plan_id, cycle_id, manifest_blob, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            manifest.manifest_digest.as_bytes().as_slice(),
                            manifest.plan_id.as_str(),
                            manifest.cycle_id.as_str(),
                            blob,
                            manifest.prepared_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendRollbackManifest(manifest) => {
                let blob = encode_rollback_manifest(manifest).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO rollback_manifests
                         (manifest_id, plan_id, cycle_id, parent_plan_id, manifest_blob, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            manifest.manifest.digest.as_bytes().as_slice(),
                            manifest.plan_id.as_str(),
                            manifest.cycle_id.as_str(),
                            manifest.parent_plan_id.as_str(),
                            blob,
                            manifest.created_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendRetirementManifest(manifest) => {
                let blob = encode_retirement_manifest(manifest).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO retirement_manifests
                         (manifest_id, plan_id, cycle_id, manifest_blob, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            manifest.manifest.digest.as_bytes().as_slice(),
                            manifest.plan_id.as_str(),
                            manifest.cycle_id.as_str(),
                            blob,
                            manifest.created_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendRoutingSnapshot(snapshot) => {
                let blob = encode_routing_snapshot(snapshot).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO routing_snapshots
                         (routing_unit_digest, routing_generation, snapshot_blob, committed_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            unit_digest.as_bytes().as_slice(),
                            u64_to_i64(snapshot.routing_generation.get())?,
                            blob,
                            snapshot.committed_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
                if !advances_head && matches!(commit.plan().cycle_kind, MigrationCycleKind::Forward)
                {
                    transaction
                        .execute(
                            "INSERT INTO routing_head
                             (routing_unit_digest, routing_generation)
                             VALUES (?1, ?2)",
                            params![
                                unit_digest.as_bytes().as_slice(),
                                u64_to_i64(snapshot.routing_generation.get())?,
                            ],
                        )
                        .map_err(map_write_error)?;
                }
            }
            MigrationMutation::AdvanceRoutingHead {
                unit_digest,
                expected,
                next,
            } => {
                let changed = transaction
                    .execute(
                        "UPDATE routing_head
                         SET routing_generation = ?1
                         WHERE routing_unit_digest = ?2 AND routing_generation = ?3",
                        params![
                            u64_to_i64(next.get())?,
                            unit_digest.as_bytes().as_slice(),
                            u64_to_i64(expected.get())?,
                        ],
                    )
                    .map_err(map_write_error)?;
                if changed != 1 {
                    return Err(MigrationStoreError::IntegrityViolation);
                }
            }
            MigrationMutation::InsertRuntimeBinding(binding) => {
                let (aggregate_type, aggregate_id) = aggregate_parts(&binding.aggregate_id)?;
                let blob = encode_runtime_binding(binding).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO runtime_bindings
                         (aggregate_type, aggregate_id, routing_unit_digest,
                          routing_generation, binding_blob)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            aggregate_type,
                            aggregate_id.as_slice(),
                            unit_digest.as_bytes().as_slice(),
                            u64_to_i64(binding.routing_generation.get())?,
                            blob,
                        ],
                    )
                    .map_err(map_write_error)?;
            }
        }
    }
    Ok(())
}

fn insert_plan(
    transaction: &Transaction<'_>,
    plan: &MigrationPlan,
) -> Result<(), MigrationStoreError> {
    let blob = encode_migration_plan(plan).map_err(map_codec_error)?;
    let (cycle_kind, parent_cycle_id) = cycle_parts(&plan.cycle_kind);
    transaction
        .execute(
            "INSERT INTO migration_plans
             (plan_id, cycle_id, cycle_kind, parent_cycle_id, source_generation,
              candidate_generation, phase, status, routing_unit_digest,
              gate_policy, plan_version, created_at, plan_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                plan.plan_id.as_str(),
                plan.cycle_id.as_str(),
                cycle_kind,
                parent_cycle_id,
                plan.source.as_str(),
                plan.candidate.as_str(),
                phase_tag(plan.phase),
                status_tag(plan.status),
                plan.routing_unit.digest().as_bytes().as_slice(),
                plan.gate_policy.as_str(),
                u64_to_i64(plan.plan_version)?,
                plan.created_at.as_unix_micros(),
                blob,
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}
