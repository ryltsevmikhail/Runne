#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn list_pending_approvals(
    state: State<'_, Arc<AppCore>>,
) -> Result<Vec<runne_app_core::CanonicalApprovalSummary>, IpcError> {
    state.list_pending_approvals().await.map_err(|_| IpcError {
        code: "approvals_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_approval(
    state: State<'_, Arc<AppCore>>,
    approval_id: String,
) -> Result<runne_app_core::CanonicalApprovalSummary, IpcError> {
    state.get_approval(&approval_id).await.map_err(|_| IpcError {
        code: "approval_unavailable",
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RespondToApprovalRequest {
    approval_id: String,
    expected_version: u64,
    decision: String,
    action_digest: String,
    policy_revision: u64,
    renderer_generation: u64,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn respond_to_approval(
    window: WebviewWindow,
    selections: State<'_, DirectorySelectionManager>,
    state: State<'_, Arc<AppCore>>,
    request: RespondToApprovalRequest,
) -> Result<runne_app_core::CanonicalApprovalDecisionAcknowledgement, IpcError> {
    if !window.is_focused().map_err(|_| approval_rejected())?
        || selections.renderer_generations().current(window.label()).ok() != Some(request.renderer_generation)
    {
        return Err(approval_rejected());
    }
    let decision = parse_approval_decision(&request.decision)?;
    state
        .respond_to_approval(
            &request.approval_id,
            request.expected_version,
            decision,
            &request.action_digest,
            request.policy_revision,
            request.renderer_generation,
        )
        .await
        .map(Into::into)
        .map_err(|_| approval_rejected())
}

fn parse_approval_decision(value: &str) -> Result<runne_app_core::ApprovalDecisionDto, IpcError> {
    match value {
        "approve" => Ok(runne_app_core::ApprovalDecisionDto::Approve),
        "deny" => Ok(runne_app_core::ApprovalDecisionDto::Deny),
        _ => Err(approval_rejected()),
    }
}

const fn approval_rejected() -> IpcError { IpcError { code: "approval_decision_rejected" } }

#[cfg(test)]
mod approval_command_tests {
    use super::parse_approval_decision;
    use runne_app_core::ApprovalDecisionDto;

    #[test]
    fn approval_decision_parser_accepts_only_published_values() {
        assert_eq!(parse_approval_decision("approve").ok(), Some(ApprovalDecisionDto::Approve));
        assert_eq!(parse_approval_decision("deny").ok(), Some(ApprovalDecisionDto::Deny));
        assert!(parse_approval_decision("approved").is_err());
        assert!(parse_approval_decision("approve\n").is_err());
    }
}
