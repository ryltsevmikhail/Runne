use crate::ports::{
    ProjectWorkspaceRepositoryError, RootAdmissionAuthorizer, RootAdmissionConsumption,
    RootAdmissionLease, RootAdmissionVerifierError,
};
use gocode_api::{
    ProjectCommandContext, RootAdmissionAction, RootAdmissionVerificationContext,
    VerifiedRootAdmissionClaims,
};
use gocode_domain::id::WorkspaceId;

pub(super) struct VerifiedRootAdmissionAuthorizer<L> {
    lease: L,
    claims: VerifiedRootAdmissionClaims,
    principal_digest: [u8; 32],
    workspace_id: WorkspaceId,
    expected_version: u64,
}

impl<L: RootAdmissionLease> VerifiedRootAdmissionAuthorizer<L> {
    pub(super) fn new(
        lease: L,
        claims: VerifiedRootAdmissionClaims,
        command: &ProjectCommandContext,
        workspace_id: WorkspaceId,
        expected_version: u64,
    ) -> Self {
        Self {
            lease,
            claims,
            principal_digest: RootAdmissionVerificationContext::principal_digest_for(
                command.principal.as_str(),
            ),
            workspace_id,
            expected_version,
        }
    }
}

impl<L: RootAdmissionLease> RootAdmissionAuthorizer for VerifiedRootAdmissionAuthorizer<L> {
    fn authorize_root_admission(
        &mut self,
    ) -> Result<RootAdmissionConsumption, ProjectWorkspaceRepositoryError> {
        let current = self
            .lease
            .current_root_admission_context()
            .map_err(map_lease_error)?;
        let claim = self.claims.context();
        let bindings_match = claim.authority_digest() == current.authority_digest()
            && claim.session_id() == current.session_id()
            && claim.launch_generation() == current.launch_generation()
            && claim.principal_digest() == current.principal_digest()
            && claim.principal_digest() == self.principal_digest
            && claim.capability_version() == current.capability_version()
            && claim.policy_version() == current.policy_version()
            && claim.gate_epoch() == current.gate_epoch()
            && claim.now_unix_millis() <= current.now_unix_millis()
            && self.claims.expires_at_unix_millis() > current.now_unix_millis()
            && self.claims.action() == RootAdmissionAction::WorkspaceBindRoot
            && self.claims.workspace_id() == self.workspace_id
            && self.claims.expected_version() == self.expected_version;
        bindings_match
            .then(|| RootAdmissionConsumption::from_claims(&self.claims))
            .ok_or(ProjectWorkspaceRepositoryError::Forbidden)
    }
}

fn map_lease_error(error: RootAdmissionVerifierError) -> ProjectWorkspaceRepositoryError {
    match error {
        RootAdmissionVerifierError::Rejected => ProjectWorkspaceRepositoryError::Forbidden,
        RootAdmissionVerifierError::Unavailable => ProjectWorkspaceRepositoryError::Unavailable,
    }
}
