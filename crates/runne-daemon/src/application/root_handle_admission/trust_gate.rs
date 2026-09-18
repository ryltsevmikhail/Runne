//! T1 pre-read trust gate for the root-admission gateway (plan 18 §T1).
//!
//! One runtime-owned policy authority per daemon process, established over
//! the durable sidecar store ports. Stage-1 `admit_source` runs on metadata
//! only, before any root handle is opened or content is read. Admission
//! always performs a fresh durable load: there is no client-supplied trusted
//! flag, and the permission mode at this boundary is a runtime-owned constant
//! that can never lift a deny.

use std::sync::Arc;

use runne_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError,
};
use runne_application::project_trust::{
    PermissionMode, ProjectTrustProjectId, SourceAdmission, SourceAdmissionRequest,
    SourceChannel, TrustAdmissionError,
};
use runne_domain::id::WorkspaceId;
use runne_platform_desktop::VerifiedRootHandle;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;

use super::diff_baseline::WorkspaceBaseline;
use super::{PRINCIPAL, RootAdmissionGateway, RootHandleAdmissionAuthority};

/// Runtime-owned holder of the single trust policy authority.
///
/// `None` is fail-closed: without the durable authority no project source is
/// admitted and no workspace content is pre-read.
#[derive(Clone)]
pub(crate) struct TrustGate(Option<Arc<ProjectTrustPolicyAuthority>>);

/// Typed outcome of a pre-read admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustSourceError {
    /// Policy denied the source (untrusted, managed deny, frozen sensitive
    /// path, unavailable channel, or ambiguous path).
    Denied,
    /// The workspace is unknown; mirrors the repository's NotFound mapping.
    NotFound,
    /// The authority or its durable state cannot be consulted (fail-closed).
    Unavailable,
}

impl TrustSourceError {
    /// Maps the gate outcome onto the workspace file host surface.
    pub(super) fn into_files(self) -> runne_api::WorkspaceFileHostError {
        match self {
            Self::Denied => runne_api::WorkspaceFileHostError::Forbidden,
            Self::NotFound => runne_api::WorkspaceFileHostError::NotFound,
            Self::Unavailable => runne_api::WorkspaceFileHostError::Unavailable,
        }
    }

    /// Maps the gate outcome onto the workspace diff host surface.
    pub(super) fn into_diff(self) -> runne_api::WorkspaceDiffHostError {
        match self {
            Self::Denied => runne_api::WorkspaceDiffHostError::Forbidden,
            Self::NotFound => runne_api::WorkspaceDiffHostError::NotFound,
            Self::Unavailable => runne_api::WorkspaceDiffHostError::Unavailable,
        }
    }

    /// Maps the gate outcome onto the workspace editor host surface.
    pub(super) fn into_editor(self) -> runne_api::WorkspaceEditorHostError {
        match self {
            Self::Denied => runne_api::WorkspaceEditorHostError::Forbidden,
            Self::NotFound => runne_api::WorkspaceEditorHostError::NotFound,
            Self::Unavailable => runne_api::WorkspaceEditorHostError::Unavailable,
        }
    }
}

impl TrustGate {
    /// Fail-closed gate without a durable authority.
    pub(crate) fn closed() -> Self {
        Self(None)
    }

    /// Installs the single policy authority.
    pub(crate) fn open(authority: Arc<ProjectTrustPolicyAuthority>) -> Self {
        Self(Some(authority))
    }

    fn admit(
        &self,
        project: ProjectTrustProjectId,
        channel: SourceChannel,
        path: Option<&str>,
    ) -> Result<SourceAdmission, TrustSourceError> {
        let Some(authority) = &self.0 else {
            return Err(TrustSourceError::Denied);
        };
        authority
            .admit_source(
                project,
                SourceAdmissionRequest {
                    channel,
                    path,
                    // Fresh server-side durable load per request (observed
                    // tokens exist only inside the authority contract).
                    observed_token: None,
                    permission_mode: PermissionMode::Ask,
                },
            )
            .map_err(|error| match error {
                TrustAdmissionError::DeniedByPolicy { .. }
                | TrustAdmissionError::MissingPath
                | TrustAdmissionError::AmbiguousPath => TrustSourceError::Denied,
                TrustAdmissionError::StaleRevision { .. }
                | TrustAdmissionError::ForeignEpoch { .. }
                | TrustAdmissionError::AuthorityUnavailable => TrustSourceError::Unavailable,
            })
    }
}

impl RootHandleAdmissionAuthority {
    fn admit_workspace_source(
        &self,
        workspace_id: WorkspaceId,
        channel: SourceChannel,
        path: Option<&str>,
    ) -> Result<SourceAdmission, TrustSourceError> {
        let workspace = self
            .store
            .get_workspace(PRINCIPAL, workspace_id)
            .map_err(|error| match error {
                ProjectWorkspaceRepositoryError::NotFound => TrustSourceError::NotFound,
                _ => TrustSourceError::Unavailable,
            })?;
        self.trust.admit(
            ProjectTrustProjectId::from_bytes(*workspace.project_id().as_bytes()),
            channel,
            path,
        )
    }

    /// Trust-gated baseline capture for the diff channel.
    ///
    /// A denied or fail-closed project keeps an explicit `Unverified`
    /// baseline — the workspace is not pre-read at bind time, and diffs stay
    /// denied instead of fabricating a plausible empty-baseline diff. Only an
    /// approved capture (admission of the FilesList channel) reads content.
    pub(crate) fn trust_gated_baseline(
        &self,
        workspace_id: WorkspaceId,
        root: &VerifiedRootHandle,
    ) -> Result<WorkspaceBaseline, ProjectWorkspaceRepositoryError> {
        if self
            .admit_workspace_source(workspace_id, SourceChannel::FilesList, None)
            .is_err()
        {
            return Ok(WorkspaceBaseline::unverified());
        }
        WorkspaceBaseline::capture(root).map_err(|_| ProjectWorkspaceRepositoryError::Unavailable)
    }
}

impl RootAdmissionGateway {
    /// Stage-1 pre-read admission; must run before any root access.
    pub(super) fn admit_workspace_source(
        &self,
        workspace_id: WorkspaceId,
        channel: SourceChannel,
        path: Option<&str>,
    ) -> Result<SourceAdmission, TrustSourceError> {
        let Some(authority) = &self.0 else {
            return Err(TrustSourceError::Unavailable);
        };
        authority.admit_workspace_source(workspace_id, channel, path)
    }
}
