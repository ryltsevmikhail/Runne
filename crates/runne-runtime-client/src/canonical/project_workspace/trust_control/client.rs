use super::{
    types::{
        ProjectTrustControlRequestDto as Decision, ProjectTrustControlSnapshotDto,
        ProjectTrustDecisionDto,
    },
    wire::{DecisionWire, SnapshotWire},
};
use crate::canonical::{
    AuthenticatedRuntimeClient, RuntimeApiError, RuntimeApiErrorKind, read_success_json,
};
use reqwest::header::CONTENT_TYPE;

impl AuthenticatedRuntimeClient {
    /// Reads safe trust metadata. It performs no trust mutation.
    pub async fn get_project_trust(
        &self,
        project: crate::canonical::CanonicalId,
        workspace: crate::canonical::CanonicalId,
    ) -> Result<ProjectTrustControlSnapshotDto, RuntimeApiError> {
        let url = format!("/v1/projects/{project}/workspaces/{workspace}/trust");
        let response = self
            .authenticated_request(self.http_client().get(self.url(&url)))?
            .send()
            .await
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::Unavailable))?;
        let snapshot = ProjectTrustControlSnapshotDto::try_from(
            read_success_json::<SnapshotWire>(response, &[200]).await?,
        )?;
        (snapshot.project_id() == project && snapshot.workspace_id() == workspace)
            .then_some(snapshot)
            .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
    }

    /// Sends one explicit control CAS, with no canonical command receipt or retry.
    /// Any transport/server ambiguity returns `UnknownAfterSend` for readback.
    pub async fn decide_project_trust(
        &self,
        request: Decision,
    ) -> Result<ProjectTrustControlSnapshotDto, RuntimeApiError> {
        let url = format!(
            "/v1/projects/{}/workspaces/{}/trust",
            request.project_id, request.workspace_id
        );
        let body = serde_json::to_vec(&DecisionWire::from(&request))
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let builder = self
            .authenticated_request(self.http_client().post(self.url(&url)))?
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        let response = builder.send().await.map_err(|_| unknown_after_send())?;
        let snapshot = match read_success_json::<SnapshotWire>(response, &[200]).await {
            Ok(value) => {
                ProjectTrustControlSnapshotDto::try_from(value).map_err(|_| unknown_after_send())?
            }
            Err(error)
                if matches!(
                    error.kind(),
                    RuntimeApiErrorKind::Unavailable | RuntimeApiErrorKind::InvalidResponse
                ) =>
            {
                return Err(unknown_after_send());
            }
            Err(error) => return Err(error),
        };
        let expected_status = match request.decision {
            ProjectTrustDecisionDto::ConfirmProject => super::types::ProjectTrustStatusDto::Trusted,
            ProjectTrustDecisionDto::RevokeProject => {
                super::types::ProjectTrustStatusDto::Untrusted
            }
        };
        let expected_revision = request.expected_revision.checked_add(1);
        let valid = snapshot.project_id() == request.project_id
            && snapshot.workspace_id() == request.workspace_id
            && snapshot.epoch() == request.expected_epoch
            && Some(snapshot.revision()) == expected_revision
            && snapshot.project_version() == request.expected_project_version
            && snapshot.workspace_version() == request.expected_workspace_version
            && snapshot.status() == expected_status
            && snapshot.managed_deny_mask() == 0
            && snapshot.provenance() == "user"
            && (request.decision != ProjectTrustDecisionDto::ConfirmProject
                || (request.expected_root_admission_version.is_some()
                    && snapshot.root_admission_version()
                        == request.expected_root_admission_version));
        valid.then_some(snapshot).ok_or_else(unknown_after_send)
    }
}

fn unknown_after_send() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::UnknownAfterSend)
}
