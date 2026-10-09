fn validate_approval_for_response(
    intent: &ApprovalResponseIntent,
    approval: &ApprovalSnapshot,
) -> Result<(), CliError> {
    if approval.approval_id != intent.approval_id
        || approval.state != runne_runtime_client::ApprovalStateDto::Pending
        || approval.expires_at <= unix_millis().unwrap_or(i64::MAX)
        || approval.request_version.checked_add(1).is_none()
        || approval.action_digest == [0; 32]
    {
        return Err(CliError::PermissionRecoveryConflict(intent.command_id));
    }
    Ok(())
}

fn approval_ack_matches(ack: &ApprovalAck, record: &ApprovalDecisionRecoveryRecordV1) -> bool {
    let expected_state = match record.decision {
        StoredApprovalDecision::Approve => runne_runtime_client::ApprovalStateDto::Approved,
        StoredApprovalDecision::Deny => runne_runtime_client::ApprovalStateDto::Denied,
    };
    ack.approval_id == record.approval_id
        && ack.task_run_id == record.task_run_id
        && record.expected_version.checked_add(1) == Some(ack.new_version)
        && ack.state == expected_state
}
fn render_approval_ack(
    ack: ApprovalAck,
    record: &ApprovalDecisionRecoveryRecordV1,
) -> CommandOutput {
    let state = match ack.state {
        runne_runtime_client::ApprovalStateDto::Approved => "approved",
        runne_runtime_client::ApprovalStateDto::Denied => "denied",
        _ => "unknown",
    };
    let decision = match record.decision {
        StoredApprovalDecision::Approve => "approve",
        StoredApprovalDecision::Deny => "deny",
    };
    CommandOutput::typed(
        format!(
            "approval ID: {}\nstate: {state}\ncommand ID: {}\nversion: {}",
            ack.approval_id, record.command_id, ack.new_version
        ),
        serde_json::json!({
            "approvalId": ack.approval_id,
            "taskRunId": ack.task_run_id,
            "commandId": record.command_id,
            "decision": decision,
            "state": state,
            "version": ack.new_version,
        }),
    )
}
fn unix_millis() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}
