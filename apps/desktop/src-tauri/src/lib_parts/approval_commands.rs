include!("approval_dialog.rs");

#[tauri::command]
async fn list_pending_approvals(
    state: State<'_, Arc<AppCore>>,
) -> Result<Vec<runne_app_core::CanonicalApprovalSummary>, IpcError> {
    state.list_pending_approvals().await.map_err(|_| IpcError {
        code: "approvals_unavailable",
    })
}

#[tauri::command]
async fn get_approval(
    state: State<'_, Arc<AppCore>>,
    approval_id: String,
) -> Result<runne_app_core::CanonicalApprovalSummary, IpcError> {
    state
        .get_approval(&approval_id)
        .await
        .map_err(|_| IpcError {
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
async fn prepare_approval_decision(
    window: WebviewWindow,
    selections: State<'_, DirectorySelectionManager>,
    intents: State<'_, crate::destructive_intent::ApprovalIntentManager>,
    state: State<'_, Arc<AppCore>>,
    request: RespondToApprovalRequest,
) -> Result<crate::destructive_intent::ApprovalIntentId, IpcError> {
    approval_window_is_current(&window, &selections, request.renderer_generation)?;
    let decision = parse_approval_decision(&request.decision)?;
    let binding = state
        .prepare_approval_confirmation(
            &request.approval_id,
            request.expected_version,
            decision,
            &request.action_digest,
            request.policy_revision,
            request.renderer_generation,
        )
        .await
        .map_err(|_| approval_rejected())?;
    if !native_approval_confirmation(&window, &binding).await {
        return Err(approval_rejected());
    }
    intents
        .prepare(
            window.label(),
            request.renderer_generation,
            binding,
            std::time::SystemTime::now(),
        )
        .map_err(|_| approval_rejected())
}

#[tauri::command]
async fn consume_approval_decision(
    window: WebviewWindow,
    selections: State<'_, DirectorySelectionManager>,
    intents: State<'_, crate::destructive_intent::ApprovalIntentManager>,
    state: State<'_, Arc<AppCore>>,
    intent: crate::destructive_intent::ApprovalIntentId,
    request: RespondToApprovalRequest,
) -> Result<runne_app_core::CanonicalApprovalDecisionAcknowledgement, IpcError> {
    approval_window_is_current(&window, &selections, request.renderer_generation)?;
    let decision = parse_approval_decision(&request.decision)?;
    let binding = state
        .prepare_approval_confirmation(
            &request.approval_id,
            request.expected_version,
            decision,
            &request.action_digest,
            request.policy_revision,
            request.renderer_generation,
        )
        .await
        .map_err(|_| approval_rejected())?;
    let issued = intents
        .consume(
            &intent,
            window.label(),
            request.renderer_generation,
            &binding,
            std::time::SystemTime::now(),
        )
        .map_err(|_| approval_rejected())?;
    state
        .commit_approval_confirmation(&issued)
        .await
        .map(Into::into)
        .map_err(|_| approval_rejected())
}

fn approval_window_is_current(
    window: &WebviewWindow,
    selections: &DirectorySelectionManager,
    generation: u64,
) -> Result<(), IpcError> {
    if !window.is_focused().map_err(|_| approval_rejected())?
        || selections
            .renderer_generations()
            .current(window.label())
            .ok()
            != Some(generation)
    {
        return Err(approval_rejected());
    }
    Ok(())
}

fn parse_approval_decision(value: &str) -> Result<runne_app_core::ApprovalDecisionDto, IpcError> {
    match value {
        "approve" => Ok(runne_app_core::ApprovalDecisionDto::Approve),
        "deny" => Ok(runne_app_core::ApprovalDecisionDto::Deny),
        _ => Err(approval_rejected()),
    }
}

const fn approval_rejected() -> IpcError {
    IpcError {
        code: "approval_decision_rejected",
    }
}

#[cfg(not(test))]
async fn native_approval_confirmation(
    window: &WebviewWindow,
    binding: &runne_app_core::ApprovalConfirmationBinding,
) -> bool {
    use tauri_plugin_dialog::{MessageDialogButtons, MessageDialogKind};
    let handle = window.app_handle().clone();
    let parent = window.clone();
    let spec = approval_dialog_spec(binding);
    tauri::async_runtime::spawn_blocking(move || {
        let result = handle
            .dialog()
            .message(spec.message)
            .title(spec.title)
            .parent(&parent)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                spec.confirm_label,
                "Cancel".into(),
            ))
            .blocking_show();
        dialog_result(Ok(result))
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
fn native_approval_confirmation(
    _: &WebviewWindow,
    _: &runne_app_core::ApprovalConfirmationBinding,
) -> std::future::Ready<bool> {
    std::future::ready(true)
}

#[cfg(test)]
#[path = "approval_commands/tests.rs"]
mod approval_command_tests;
