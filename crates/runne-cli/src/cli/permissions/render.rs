fn render_permission_mode_status(status: PermissionModeStatusV1) -> CommandOutput {
    let selected = permission_mode_label(status.selected_mode);
    let effective = match &status.effective {
        runne_runtime_client::PermissionEffectiveStateV1::NotReady { reason } => {
            format!("not ready ({reason:?})")
        }
        runne_runtime_client::PermissionEffectiveStateV1::Ready { mode, .. } => {
            format!("ready ({})", permission_mode_label(*mode))
        }
    };
    let text = format!(
        "selected mode: {selected}\neffective state: {effective}\nauthorization revision: {}\npreset version: {}\nmanaged policy version: {}\npending approvals: {}\nnetwork state: {:?}\nexpires at (Unix ms): {}",
        status.authorization_revision,
        status.preset_version.as_u16(),
        status.managed_policy_version,
        status.pending_approval_ids.len(),
        status.network_state,
        status
            .expires_at_unix_ms
            .map_or_else(|| "none".to_owned(), |expiry| expiry.to_string()),
    );
    let data = serde_json::to_value(status).expect("permission status DTO is serializable");
    CommandOutput::typed(text, data)
}

fn render_permission_command_status(status: PermissionModeCommandStatusV2) -> CommandOutput {
    use std::fmt::Write as _;

    let (command_id, state, native_action_required, expires_at) = match &status {
        PermissionModeCommandStatusV2::PendingNativeConfirmation {
            command_id,
            expires_at_unix_ms,
        } => (
            *command_id,
            "pending_native_confirmation",
            true,
            Some(*expires_at_unix_ms),
        ),
        PermissionModeCommandStatusV2::PendingReauthentication {
            command_id,
            expires_at_unix_ms,
        } => (
            *command_id,
            "pending_reauthentication",
            true,
            Some(*expires_at_unix_ms),
        ),
        PermissionModeCommandStatusV2::Committed { receipt } => {
            (receipt.command_id, "committed", false, None)
        }
        PermissionModeCommandStatusV2::Cancelled { command_id } => {
            (*command_id, "cancelled", false, None)
        }
        PermissionModeCommandStatusV2::Expired { command_id } => {
            (*command_id, "expired", false, None)
        }
        PermissionModeCommandStatusV2::Invalidated { command_id } => {
            (*command_id, "invalidated", false, None)
        }
    };
    let mut data = serde_json::to_value(status).expect("permission command DTO is serializable");
    if let Some(fields) = data.as_object_mut() {
        fields.insert(
            "nativeActionRequired".to_owned(),
            serde_json::json!(native_action_required),
        );
    }
    let mut text = format!("command ID: {command_id}\nstate: {state}");
    if native_action_required {
        text.push_str("\nnative action: required; complete it in the trusted native host");
        if let Some(deadline) = expires_at {
            let _ = write!(text, "\nexpires at (Unix ms): {deadline}");
        }
    }
    if state == "committed" {
        text.push_str("\ncurrent effective state: read permissions status separately");
    }
    CommandOutput::typed(text, data)
}

fn render_pending_approvals(approvals: Vec<ApprovalSummaryDto>) -> CommandOutput {
    let mut rows = Vec::with_capacity(approvals.len());
    let mut text_rows = Vec::with_capacity(approvals.len());
    for approval in approvals {
        let state = match approval.state() {
            runne_runtime_client::ApprovalStateDto::Pending => "pending",
            runne_runtime_client::ApprovalStateDto::Approved => "approved",
            runne_runtime_client::ApprovalStateDto::Denied => "denied",
            runne_runtime_client::ApprovalStateDto::Expired => "expired",
            runne_runtime_client::ApprovalStateDto::Cancelled => "cancelled",
        };
        let action = approval.action();
        let resource = approval.resource();
        let risk_summary = approval.risk_summary();
        rows.push(serde_json::json!({
            "approvalId": approval.approval_id(),
            "taskRunId": approval.task_run_id(),
            "attemptId": approval.attempt_id(),
            "invocationId": approval.invocation_id(),
            "action": action,
            "resource": resource,
            "actionDigest": format_digest(approval.action_digest()),
            "policyRevision": approval.policy_revision(),
            "requestVersion": approval.request_version(),
            "expiresAtUnixMs": approval.expires_at(),
            "riskSummary": risk_summary,
            "state": state,
            "requiresDecision": approval.requires_decision(),
        }));
        text_rows.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            approval.approval_id(),
            state,
            escape_terminal_reason_text(action),
            escape_terminal_reason_text(resource),
            escape_terminal_reason_text(risk_summary),
        ));
    }
    let text = if text_rows.is_empty() {
        "no pending approvals".to_owned()
    } else {
        text_rows.join("\n")
    };
    CommandOutput::typed(text, serde_json::json!({ "approvals": rows }))
}

const fn permission_mode_label(mode: runne_runtime_client::PermissionModeV1) -> &'static str {
    match mode {
        runne_runtime_client::PermissionModeV1::AskAlways => "Запрашивать разрешение",
        runne_runtime_client::PermissionModeV1::RiskBased => "Подтверждать за меня",
        runne_runtime_client::PermissionModeV1::FullAccess => "Полный доступ",
    }
}

fn format_digest(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(64);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    result
}
