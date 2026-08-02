fn stage_output(outcome: MigrationCommandOutcome) -> Result<StagePlanOutput, MigrationError> {
    let snapshot = outcome
        .routing_snapshot
        .ok_or(MigrationError::StorageContractViolation)?;
    Ok(StagePlanOutput {
        plan: outcome.plan,
        snapshot,
        transition_id: outcome.transition_id,
    })
}

fn record_evidence_output(outcome: MigrationCommandOutcome) -> RecordEvidenceOutput {
    RecordEvidenceOutput {
        plan: outcome.plan,
        transition_id: outcome.transition_id,
    }
}

fn advance_output(outcome: MigrationCommandOutcome) -> AdvancePhaseOutput {
    AdvancePhaseOutput {
        plan: outcome.plan,
        snapshot: outcome.routing_snapshot,
        transition_id: outcome.transition_id,
    }
}

fn start_rollback_output(
    outcome: MigrationCommandOutcome,
) -> Result<StartRollbackOutput, MigrationError> {
    let snapshot = outcome
        .routing_snapshot
        .ok_or(MigrationError::StorageContractViolation)?;
    Ok(StartRollbackOutput {
        plan: outcome.plan,
        snapshot,
        transition_id: outcome.transition_id,
    })
}

fn commit_outcome(result: MigrationCommitResult) -> MigrationCommandOutcome {
    match result {
        MigrationCommitResult::Committed { receipt } => receipt.stored_result,
        MigrationCommitResult::Duplicate { stored_result } => stored_result,
    }
}

fn audit_record(
    context: &MigrationCommandContext,
    plan: &MigrationPlan,
    action: MigrationAuditAction,
    fingerprint: &MigrationCommandFingerprint,
) -> MigrationAuditRecord {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_RECORD_PREFIX);
    update_length_prefixed(&mut hasher, context.command_id.to_string().as_bytes());
    hasher.update(fingerprint.as_bytes());
    MigrationAuditRecord {
        record_id: ArtifactDigest::from_bytes(hasher.finalize().into()),
        plan_id: plan.plan_id.clone(),
        command_id: context.command_id,
        operator_id: context.operator_id.clone(),
        action,
        recorded_at: context.evaluated_at,
    }
}

fn transition_identity(
    context: &MigrationCommandContext,
    fingerprint: &MigrationCommandFingerprint,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_RECORD_PREFIX);
    update_length_prefixed(&mut hasher, context.command_id.to_string().as_bytes());
    hasher.update(fingerprint.as_bytes());
    ArtifactDigest::from_bytes(hasher.finalize().into()).to_string()
}

fn fingerprint(tag: u8, fields: Vec<Vec<u8>>) -> MigrationCommandFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(COMMAND_FINGERPRINT_PREFIX);
    hasher.update([tag]);
    for field in fields {
        update_length_prefixed(&mut hasher, &field);
    }
    MigrationCommandFingerprint::from_bytes(hasher.finalize().into())
}
