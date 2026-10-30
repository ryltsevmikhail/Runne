//! Principal-bound exact filesystem identity lookup.
use super::{WorkspaceSnapshotDto, wire::WorkspaceWire};
use crate::canonical::{
    AuthenticatedRuntimeClient, RuntimeApiError, RuntimeApiErrorKind, read_success_json,
};

impl AuthenticatedRuntimeClient {
    /// Finds the unique live Workspace whose admitted filesystem identity matches.
    pub async fn find_workspace_by_root(
        &self,
        digest: [u8; 32],
    ) -> Result<Option<WorkspaceSnapshotDto>, RuntimeApiError> {
        if digest == [0; 32] || !crate::canonical::protected_profile_matches(self) {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        }
        let response = self
            .authenticated_request(self.http_client().get(self.url(&format!(
                "/v1/workspace-root-identities/{}",
                hex::encode(digest)
            ))))?
            .send()
            .await
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::Unavailable))?;
        read_success_json::<Option<WorkspaceWire>>(response, &[200])
            .await?
            .map(WorkspaceSnapshotDto::try_from)
            .transpose()
    }
}
