#[expect(
    clippy::future_not_send,
    reason = "the approval dialog must run inline on the CLI main thread"
)]
async fn execute_approval_response<R: ApprovalResponseRuntime>(
    runtime: &R,
    intent: ApprovalResponseIntent,
) -> Result<CommandOutput, CliError> {
    #[cfg(target_os = "linux")]
    {
        let state_dir =
            dirs::state_dir().ok_or(CliError::PermissionRecoveryIo(intent.command_id))?;
        let index = LinuxPermissionRecoveryIndex::new(state_dir);
        #[cfg(test)]
        if std::env::var("RUNNE_CLI_MOCK_APPROVAL_CONSENT").as_deref()
            == Ok("approval-crash-fixture")
        {
            return crate::protected_runtime_tests::approval_crash::execute_with_mock_consent(
                runtime, intent, &index,
            )
            .await;
        }
        execute_approval_response_with_consent(runtime, intent, &index, &NativeApprovalConsent)
            .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = runtime;
        Err(CliError::PermissionCommandUnavailable(intent.command_id))
    }
}

#[expect(
    clippy::future_not_send,
    reason = "the approval dialog must run inline on the CLI main thread"
)]
async fn execute_approval_response_with_consent<
    R: ApprovalResponseRuntime,
    I: PermissionRecoveryIndex,
    C: ApprovalConsent,
>(
    runtime: &R,
    intent: ApprovalResponseIntent,
    index: &I,
    consent: &C,
) -> Result<CommandOutput, CliError> {
    let command_id = intent.command_id;
    let session = runtime.approval_session_info();
    let stable = StableRuntimeIdentity::from_session(&session)
        .map_err(|_| CliError::PermissionCommandUnavailable(command_id))?;
    let audit = RuntimeAuditSnapshot::from_session(&session)
        .map_err(|_| CliError::PermissionCommandUnavailable(command_id))?;
    let scope = scope_digest(&stable);
    if let Some(bytes) = index
        .read_existing(&scope, command_id)
        .map_err(|error| recovery_cli_error(command_id, error))?
    {
        return reconcile_existing_approval(runtime, &intent, &stable, &bytes).await;
    }

    let approval = runtime
        .read_approval(intent.approval_id)
        .await
        .map_err(|error| approval_read_error(command_id, error))?;
    validate_approval_for_response(&intent, &approval)?;
    let review_digest = approval_review_digest(&intent, &approval, &stable);
    let token = consent
        .present(&intent, &approval, review_digest)
        .map_err(|_| CliError::PermissionCommandUnavailable(command_id))?;

    let current = runtime
        .read_approval(intent.approval_id)
        .await
        .map_err(|error| approval_read_error(command_id, error))?;
    let current_session = runtime.approval_session_info();
    let current_stable = StableRuntimeIdentity::from_session(&current_session)
        .map_err(|_| CliError::PermissionCommandUnavailable(command_id))?;
    let current_audit = RuntimeAuditSnapshot::from_session(&current_session)
        .map_err(|_| CliError::PermissionCommandUnavailable(command_id))?;
    if current != approval || current_stable != stable || current_audit != audit {
        return Err(CliError::PermissionRecoveryConflict(command_id));
    }
    validate_approval_for_response(&intent, &current)?;
    if !consent.consume(token, review_digest, current.expires_at) {
        return Err(CliError::PermissionCommandUnavailable(command_id));
    }

    let bytes = make_approval_recovery_record(&intent, &current, stable.clone(), audit)
        .map_err(|error| recovery_cli_error(command_id, error))?;
    let record = decode_approval_recovery_record(&bytes)
        .map_err(|error| recovery_cli_error(command_id, error))?;
    match index
        .create_exclusive(&scope, command_id, &bytes)
        .map_err(|error| recovery_cli_error(command_id, error))?
    {
        RecordCreateResult::Existing(existing) => {
            reconcile_existing_approval(runtime, &intent, &stable, &existing).await
        }
        RecordCreateResult::DurableCreated => {
            #[cfg(all(test, target_os = "linux"))]
            crate::protected_runtime_tests::barrier("approval_before_post");
            match runtime.decide_approval(&record).await {
                Ok(ack) if approval_ack_matches(&ack, &record) => {
                    #[cfg(all(test, target_os = "linux"))]
                    crate::protected_runtime_tests::barrier("approval_after_commit");
                    Ok(render_approval_ack(ack, &record))
                }
                Ok(_) | Err(ApprovalRuntimeError::UnknownAfterSend) => {
                    reconcile_approval_response(runtime, &record).await
                }
                Err(ApprovalRuntimeError::Api(error)) => {
                    reconcile_after_uncertain_approval_error(error, runtime, &record).await
                }
                Err(ApprovalRuntimeError::NotFound) => {
                    Err(CliError::PermissionCommandUnknown(command_id))
                }
                Err(ApprovalRuntimeError::InvalidWitness) => {
                    Err(CliError::PermissionRecoveryCorrupt(command_id))
                }
            }
        }
    }
}

#[expect(
    clippy::future_not_send,
    reason = "approval runtime reconciliation stays inline with the main-thread prompt"
)]
async fn reconcile_existing_approval<R: ApprovalResponseRuntime>(
    runtime: &R,
    intent: &ApprovalResponseIntent,
    stable: &StableRuntimeIdentity,
    bytes: &[u8],
) -> Result<CommandOutput, CliError> {
    let record = match decode_any_command_record(bytes)
        .map_err(|error| recovery_cli_error(intent.command_id, error))?
    {
        RecoveredCommandRecord::PermissionMode(_) => {
            return Err(CliError::PermissionRecoveryConflict(intent.command_id));
        }
        RecoveredCommandRecord::ApprovalDecision(record) => record,
    };
    match_approval_recovery_record(&record, intent, stable)?;
    reconcile_approval_response(runtime, &record).await
}

#[expect(
    clippy::future_not_send,
    reason = "approval runtime reconciliation stays inline with the main-thread prompt"
)]
async fn reconcile_after_uncertain_approval_error<R: ApprovalResponseRuntime>(
    error: RuntimeApiError,
    runtime: &R,
    record: &ApprovalDecisionRecoveryRecordV1,
) -> Result<CommandOutput, CliError> {
    match error.kind() {
        RuntimeApiErrorKind::UnknownAfterSend
        | RuntimeApiErrorKind::OutcomeUnknown
        | RuntimeApiErrorKind::Unavailable
        | RuntimeApiErrorKind::InvalidResponse
        | RuntimeApiErrorKind::ResponseTooLarge => {
            reconcile_approval_response(runtime, record).await
        }
        _ => Err(CliError::Api(error)),
    }
}

#[expect(
    clippy::future_not_send,
    reason = "approval runtime reconciliation stays inline with the main-thread prompt"
)]
async fn reconcile_approval_response<R: ApprovalResponseRuntime>(
    runtime: &R,
    record: &ApprovalDecisionRecoveryRecordV1,
) -> Result<CommandOutput, CliError> {
    match runtime
        .reconcile_approval(record)
        .await
        .map_err(|error| approval_runtime_cli_error(record.command_id, error))?
    {
        ApprovalReconciliation::DurablyRecorded(ack) if approval_ack_matches(&ack, record) => {
            Ok(render_approval_ack(ack, record))
        }
        ApprovalReconciliation::NotCommittedRetryable
        | ApprovalReconciliation::Indeterminate
        | ApprovalReconciliation::Unexpected
        | ApprovalReconciliation::DurablyRecorded(_) => {
            Err(CliError::PermissionCommandUnknown(record.command_id))
        }
    }
}

fn approval_decision_request(
    record: &ApprovalDecisionRecoveryRecordV1,
) -> Result<runne_runtime_client::ApprovalDecisionRequest, ApprovalRuntimeError> {
    let identity = runne_runtime_client::CommandIdentity::new(
        record.command_id,
        record.idempotency_key.clone(),
    )
    .map_err(|_| ApprovalRuntimeError::InvalidWitness)?;
    let action_digest = hex::decode(&record.action_digest)
        .map_err(|_| ApprovalRuntimeError::InvalidWitness)?
        .try_into()
        .map_err(|_| ApprovalRuntimeError::InvalidWitness)?;
    runne_runtime_client::ApprovalDecisionRequest::new(
        identity,
        record.approval_id,
        record.expected_version,
        record.decision.into(),
        action_digest,
        record.policy_revision,
        record.approval_generation,
    )
    .map_err(|_| ApprovalRuntimeError::InvalidWitness)
}

fn approval_read_error(command_id: CanonicalId, error: ApprovalRuntimeError) -> CliError {
    match error {
        ApprovalRuntimeError::NotFound => CliError::PermissionCommandUnknown(command_id),
        ApprovalRuntimeError::UnknownAfterSend => {
            CliError::PermissionCommandUnavailable(command_id)
        }
        ApprovalRuntimeError::InvalidWitness => CliError::PermissionRecoveryCorrupt(command_id),
        ApprovalRuntimeError::Api(error) => CliError::Api(error),
    }
}

fn approval_runtime_cli_error(command_id: CanonicalId, error: ApprovalRuntimeError) -> CliError {
    match error {
        ApprovalRuntimeError::NotFound
        | ApprovalRuntimeError::UnknownAfterSend
        | ApprovalRuntimeError::InvalidWitness => CliError::PermissionCommandUnknown(command_id),
        ApprovalRuntimeError::Api(error) => CliError::Api(error),
    }
}

fn approval_send_error(error: RuntimeApiError) -> ApprovalRuntimeError {
    match error.kind() {
        RuntimeApiErrorKind::UnknownAfterSend => ApprovalRuntimeError::UnknownAfterSend,
        _ => ApprovalRuntimeError::Api(error),
    }
}

fn approval_review_digest(
    intent: &ApprovalResponseIntent,
    approval: &ApprovalSnapshot,
    stable: &StableRuntimeIdentity,
) -> [u8; 32] {
    let mut hash = sha2::Sha256::new();
    hash.update(b"runne:d21:cli-approval-human-review:v1\0");
    approval_digest_common(
        &mut hash,
        &intent.command_id.to_string(),
        &intent.idempotency_key,
        stable,
    );
    approval_review_tuple(&mut hash, approval);
    put_digest_bytes(&mut hash, approval.action.as_bytes());
    put_digest_bytes(&mut hash, approval.resource.as_bytes());
    put_digest_bytes(&mut hash, approval.risk_summary.as_bytes());
    hash.update([approval_decision_tag(intent.decision)]);
    hash.finalize().into()
}

fn approval_review_tuple(hash: &mut sha2::Sha256, approval: &ApprovalSnapshot) {
    for value in [
        approval.approval_id.to_string(),
        approval.task_run_id.to_string(),
    ] {
        put_digest_bytes(hash, value.as_bytes());
    }
    let attempt = approval
        .attempt_id
        .map_or_else(String::new, |id| id.to_string());
    put_digest_bytes(hash, attempt.as_bytes());
    put_digest_bytes(hash, approval.invocation_id.to_string().as_bytes());
    put_digest_bytes(hash, &approval.action_digest);
    hash.update(approval.policy_revision.to_be_bytes());
    hash.update(approval.request_version.to_be_bytes());
    hash.update(approval.approval_generation.to_be_bytes());
    hash.update(approval.expires_at.to_be_bytes());
    hash.update([approval_state_tag(approval.state)]);
}
