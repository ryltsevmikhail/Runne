use runne_app_core::{
    ProjectTrustControlSnapshotDto as Snapshot, ProjectTrustDecisionDto as Decision,
    ProjectTrustStatusDto as Status,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrustSnapshotIpc {
    project_id: String,
    project_name: String,
    project_version: String,
    workspace_id: String,
    workspace_name: String,
    workspace_version: String,
    status: &'static str,
    managed_deny_mask: u32,
    provenance: String,
    epoch: String,
    revision: String,
    root_admission_version: Option<String>,
}

impl From<Snapshot> for TrustSnapshotIpc {
    fn from(s: Snapshot) -> Self {
        Self {
            project_id: s.project_id().to_string(), project_name: s.project_name().to_owned(),
            project_version: s.project_version().to_string(), workspace_id: s.workspace_id().to_string(),
            workspace_name: s.workspace_name().to_owned(), workspace_version: s.workspace_version().to_string(),
            status: match s.status() { Status::Untrusted => "untrusted", Status::Trusted => "trusted", Status::Managed => "managed" },
            managed_deny_mask: s.managed_deny_mask(), provenance: s.provenance().to_owned(),
            epoch: s.epoch().to_string(), revision: s.revision().to_string(),
            root_admission_version: s.root_admission_version().map(|v| v.to_string()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrustCommandOutcome { outcome: &'static str, snapshot: Option<TrustSnapshotIpc> }

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_project_trust_control(
    state: State<'_, std::sync::Arc<AppCore>>, project_id: String, workspace_id: String,
) -> Result<TrustSnapshotIpc, IpcError> {
    state.get_project_trust_control(&project_id, &workspace_id).await
        .map(TrustSnapshotIpc::from).map_err(|_| IpcError { code: "trust_control_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn request_project_trust_control(
    window: WebviewWindow, state: State<'_, std::sync::Arc<AppCore>>,
    project_id: String, workspace_id: String, action: String,
) -> Result<TrustCommandOutcome, IpcError> {
    if !window.is_focused().unwrap_or(false) { return Err(IpcError { code: "trust_confirmation_rejected" }); }
    let decision = match action.as_str() {
        "confirm_project" => Decision::ConfirmProject,
        "revoke_project" => Decision::RevokeProject,
        _ => return Err(IpcError { code: "trust_action_invalid" }),
    };
    let observed = state.get_project_trust_control(&project_id, &workspace_id).await
        .map_err(|_| IpcError { code: "trust_control_unavailable" })?;
    if observed.status() == Status::Managed || observed.managed_deny_mask() != 0 {
        return Err(IpcError { code: "managed_trust_policy" });
    }
    if decision == Decision::ConfirmProject && observed.root_admission_version().is_none() {
        return Err(IpcError { code: "trust_root_unavailable" });
    }
    let locale = match state.locale().as_deref() {
        Ok("ru") => crate::project_trust_confirmation::TrustConfirmationLocale::Russian,
        _ => crate::project_trust_confirmation::TrustConfirmationLocale::English,
    };
    if !crate::project_trust_confirmation::confirm_trust_change(&window, &observed, decision, locale).await {
        return Ok(TrustCommandOutcome { outcome: "cancelled", snapshot: None });
    }
    let request = runne_app_core::ProjectTrustControlRequestDto {
        project_id: observed.project_id(), workspace_id: observed.workspace_id(), decision,
        expected_epoch: observed.epoch(), expected_revision: observed.revision(),
        expected_project_version: observed.project_version(), expected_workspace_version: observed.workspace_version(),
        expected_root_admission_version: if decision == Decision::ConfirmProject { observed.root_admission_version() } else { None },
    };
    match state.decide_project_trust_control(request).await {
        Ok(snapshot) => Ok(TrustCommandOutcome { outcome: "updated", snapshot: Some(snapshot.into()) }),
        Err(runne_app_core::AppCoreError::TrustControlUnknownAfterSend) => Err(IpcError { code: "trust_control_unknown_after_send" }),
        Err(runne_app_core::AppCoreError::TrustControlConflict) => Err(IpcError { code: "trust_control_conflict" }),
        Err(runne_app_core::AppCoreError::TrustControlManagedPolicy) => Err(IpcError { code: "managed_trust_policy" }),
        Err(runne_app_core::AppCoreError::TrustControlRootUnavailable) => Err(IpcError { code: "trust_root_unavailable" }),
        Err(_) => Err(IpcError { code: "trust_control_refresh_required" }),
    }
}
