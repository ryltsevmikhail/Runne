//! T1 pre-read trust gate for the root-admission gateway (plan 18 §T1).
//!
//! One runtime-owned policy authority per daemon process, established over
//! the durable sidecar store ports. Stage-1 `admit_source` runs on metadata
//! only, before any root handle is opened or content is read. Admission
//! always performs a fresh durable load: there is no client-supplied trusted
//! flag, and the permission mode at this boundary is a runtime-owned constant
//! that can never lift a deny.

use std::sync::Arc;

use runne_application::ports::{ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError};
use runne_application::project_trust::{
    LocalCommandAdmission, PermissionMode, ProjectTrustEffectLease, ProjectTrustProjectId,
    SourceAdmission, SourceAdmissionRequest, SourceChannel, TrustAdmissionError, TrustToken,
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

    fn admit_local_command(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<LocalCommandAdmission, TrustSourceError> {
        let Some(authority) = &self.0 else {
            return Err(TrustSourceError::Denied);
        };
        authority
            .admit_local_command(project, None)
            .map_err(|error| match error {
                TrustAdmissionError::DeniedByPolicy { .. }
                | TrustAdmissionError::MissingPath
                | TrustAdmissionError::AmbiguousPath => TrustSourceError::Denied,
                TrustAdmissionError::StaleRevision { .. }
                | TrustAdmissionError::ForeignEpoch { .. }
                | TrustAdmissionError::AuthorityUnavailable => TrustSourceError::Unavailable,
            })
    }

    fn acquire_local_command_effect_lease(
        &self,
        project: ProjectTrustProjectId,
        expected: TrustToken,
    ) -> Result<Box<dyn ProjectTrustEffectLease>, TrustSourceError> {
        let Some(authority) = &self.0 else {
            return Err(TrustSourceError::Denied);
        };
        authority
            .acquire_local_command_effect_lease(project, expected)
            .map(|(lease, _)| lease)
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

    pub(super) fn admit_workspace_local_command(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalCommandAdmission, TrustSourceError> {
        let workspace = self
            .store
            .get_workspace(PRINCIPAL, workspace_id)
            .map_err(|error| match error {
                ProjectWorkspaceRepositoryError::NotFound => TrustSourceError::NotFound,
                _ => TrustSourceError::Unavailable,
            })?;
        self.trust
            .admit_local_command(ProjectTrustProjectId::from_bytes(
                *workspace.project_id().as_bytes(),
            ))
    }

    pub(super) fn acquire_workspace_local_command_effect_lease(
        &self,
        workspace_id: WorkspaceId,
        expected: TrustToken,
    ) -> Result<Box<dyn ProjectTrustEffectLease>, TrustSourceError> {
        let workspace = self
            .store
            .get_workspace(PRINCIPAL, workspace_id)
            .map_err(|error| match error {
                ProjectWorkspaceRepositoryError::NotFound => TrustSourceError::NotFound,
                _ => TrustSourceError::Unavailable,
            })?;
        self.trust.acquire_local_command_effect_lease(
            ProjectTrustProjectId::from_bytes(*workspace.project_id().as_bytes()),
            expected,
        )
    }

    /// Trust-gated baseline capture for the diff channel.
    ///
    /// A denied or fail-closed project keeps an explicit `Unverified`
    /// baseline — the workspace is not pre-read at bind time, and diffs stay
    /// denied instead of fabricating a plausible empty-baseline diff. Only an
    /// approved capture (admission of the FilesList channel) reads content.
    ///
    /// An approved root that cannot be captured inside the bounded inventory
    /// (a checkout with more entries than the change listing limit) also keeps
    /// `Unverified`: the recorded diff stays denied for that workspace, but
    /// binding the exact root — required by every root-gated runtime path — must
    /// not fail merely because the tree is larger than the diff bound.
    pub(super) fn trust_gated_baseline(
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
        Ok(WorkspaceBaseline::capture(root).unwrap_or_else(|_| WorkspaceBaseline::unverified()))
    }
}

impl RootAdmissionGateway {
    /// D2 target check runs frozen T1 exclusion and fresh source admission
    /// before opening metadata descriptors.
    pub(in crate::application) fn admit_d2_tool_target(
        &self,
        workspace_id: WorkspaceId,
        path: &str,
    ) -> Result<(), TrustSourceError> {
        if super::diff_baseline::sensitive_path(path) {
            return Err(TrustSourceError::Denied);
        }
        self.admit_workspace_source(workspace_id, SourceChannel::FilesRead, Some(path))
            .map(|_| ())
    }

    pub(in crate::application) fn admit_coding_tool_target(
        &self,
        workspace_id: WorkspaceId,
        tool: &str,
        path: &str,
    ) -> Result<(), TrustSourceError> {
        if matches!(
            tool,
            "workspace.files.list" | "workspace.files.search" | "workspace.command.run"
        ) {
            if path != "." && super::diff_baseline::sensitive_path(path) {
                return Err(TrustSourceError::Denied);
            }
            self.admit_workspace_source(
                workspace_id,
                SourceChannel::FilesList,
                (path != ".").then_some(path),
            )
            .map(|_| ())
        } else {
            self.admit_d2_tool_target(workspace_id, path)
        }
    }

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
