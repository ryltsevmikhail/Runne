fn cycle_parts(cycle_kind: &MigrationCycleKind) -> (i64, Option<&str>) {
    match cycle_kind {
        MigrationCycleKind::Forward => (1, None),
        MigrationCycleKind::Rollback { parent_cycle_id } => (2, Some(parent_cycle_id.as_str())),
    }
}

fn persist_result_plan(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let inserted = commit.mutations().iter().any(
        |mutation| matches!(mutation, MigrationMutation::InsertPlan(plan) if plan == commit.plan()),
    );
    if inserted {
        return Ok(());
    }
    let plan = commit.plan();
    let blob = encode_migration_plan(plan).map_err(map_codec_error)?;
    let changed = transaction
        .execute(
            "UPDATE migration_plans
             SET phase = ?1, status = ?2, plan_version = ?3, plan_blob = ?4
             WHERE plan_id = ?5",
            params![
                phase_tag(plan.phase),
                status_tag(plan.status),
                u64_to_i64(plan.plan_version)?,
                blob,
                plan.plan_id.as_str(),
            ],
        )
        .map_err(map_write_error)?;
    if changed != 1 {
        return Err(MigrationStoreError::IntegrityViolation);
    }
    Ok(())
}

fn persist_audit(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let audit = commit.audit();
    let blob = encode_migration_audit(audit).map_err(map_codec_error)?;
    transaction
        .execute(
            "INSERT INTO migration_audit
             (record_id, plan_id, command_id, operator_id, action, recorded_at, record_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                audit.record_id.as_bytes().as_slice(),
                audit.plan_id.as_str(),
                audit.command_id.as_bytes().as_slice(),
                audit.operator_id.as_str(),
                audit_action_tag(audit.action),
                audit.recorded_at.as_unix_micros(),
                blob,
            ],
        )
        .map_err(|_| MigrationStoreError::IntegrityViolation)?;
    Ok(())
}

fn persist_receipt(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let outcome = encode_migration_outcome(commit.outcome()).map_err(map_codec_error)?;
    transaction
        .execute(
            "INSERT INTO migration_receipts
             (command_id, plan_id, scope_bytes, idempotency_key, fingerprint,
              outcome_blob, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                commit.context().command_id.as_bytes().as_slice(),
                commit.plan().plan_id.as_str(),
                receipt_scope(commit.context())?,
                commit.context().idempotency_key.as_str().as_bytes(),
                commit.fingerprint().as_bytes().as_slice(),
                outcome,
                commit.audit().recorded_at.as_unix_micros(),
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}
