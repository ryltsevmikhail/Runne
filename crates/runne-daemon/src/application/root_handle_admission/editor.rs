use runne_api::{
    EditorLaunchReceipt, EditorLaunchTargetV1, OpenEditorRequest, WorkspaceEditorHostError,
};
use runne_application::ports::WorkspaceEditorProvider;

impl WorkspaceEditorProvider for RootAdmissionGateway {
    fn open_editor(
        &self,
        principal: &str,
        request: &OpenEditorRequest,
    ) -> Result<EditorLaunchReceipt, WorkspaceEditorHostError> {
        (principal == PRINCIPAL)
            .then_some(())
            .ok_or(WorkspaceEditorHostError::Forbidden)?;
        if !matches!(request.target(), EditorLaunchTargetV1::SystemDefault)
            || sensitive_path(request.relative_path())
        {
            return Err(WorkspaceEditorHostError::Forbidden);
        }
        self.with_workspace_root(request.workspace_id(), |root| {
            root.launch_system_default_editor(request.relative_path())
                .map_err(|error| match error {
                    runne_platform_desktop::RootHandleBrokerError::Rejected => {
                        WorkspaceFileHostError::NotFound
                    }
                    runne_platform_desktop::RootHandleBrokerError::Unavailable => {
                        WorkspaceFileHostError::Unavailable
                    }
                })?;
            Ok(EditorLaunchReceipt::accepted(request))
        })
        .map_err(|error| match error {
            WorkspaceFileHostError::NotFound => WorkspaceEditorHostError::NotFound,
            _ => WorkspaceEditorHostError::Unavailable,
        })
    }
}

#[cfg(test)]
mod editor_tests {
    use super::*;
    use runne_api::{EditorLaunchTargetV1, OpenEditorRequest, WorkspaceEditorHostError};
    use runne_application::ports::WorkspaceEditorProvider;
    use runne_domain::id::WorkspaceId;

    fn request(path: &str) -> OpenEditorRequest {
        OpenEditorRequest::new(
            "018f2e3a-7000-7000-8000-000000000405"
                .parse::<WorkspaceId>()
                .expect("fixture workspace id"),
            path,
            EditorLaunchTargetV1::SystemDefault,
        )
        .expect("valid editor path")
    }

    #[test]
    fn editor_rejects_non_owner_before_root_lookup() {
        let result =
            RootAdmissionGateway::unavailable().open_editor("other", &request("src/main.rs"));
        assert_eq!(result, Err(WorkspaceEditorHostError::Forbidden));
    }

    #[test]
    fn editor_rejects_sensitive_paths_before_root_lookup() {
        let result = RootAdmissionGateway::unavailable().open_editor(PRINCIPAL, &request(".env"));
        assert_eq!(result, Err(WorkspaceEditorHostError::Forbidden));
    }

    #[test]
    fn editor_fails_closed_without_an_active_root() {
        let result =
            RootAdmissionGateway::unavailable().open_editor(PRINCIPAL, &request("src/main.rs"));
        assert_eq!(result, Err(WorkspaceEditorHostError::Unavailable));
    }
}
