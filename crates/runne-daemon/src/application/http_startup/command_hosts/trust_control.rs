//! Protected trust-control host preserving trust -> canonical -> root lock order.

use std::sync::Arc;

use runne_api::{
    ApiPrincipalId, ProjectTrustControlError as Error, ProjectTrustControlHostPort,
    ProjectTrustControlProvenance as Provenance, ProjectTrustControlRequest,
    ProjectTrustControlSnapshot as Snapshot, ProjectTrustControlStatus as Status,
    ProjectTrustDecision as Decision,
};
use runne_application::{
    ports::ProjectWorkspaceRepositoryError,
    project_trust::{
        ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus, TrustPersistenceError,
    },
};
use runne_domain::id::{ProjectId, WorkspaceId};
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::ProjectWorkspaceStore;

use super::super::super::root_handle_admission::{
    PRINCIPAL, RootAdmissionGateway, TrustRootDecisionError,
};

#[derive(Clone)]
pub(super) struct TrustControlHost {
    store: ProjectWorkspaceStore,
    trust: Arc<ProjectTrustPolicyAuthority>,
    roots: RootAdmissionGateway,
}

impl TrustControlHost {
    pub(super) fn new(
        store: ProjectWorkspaceStore,
        trust: Arc<ProjectTrustPolicyAuthority>,
        roots: RootAdmissionGateway,
    ) -> Self {
        Self {
            store,
            trust,
            roots,
        }
    }

    fn check_principal(principal: &ApiPrincipalId) -> Result<(), Error> {
        (principal.as_str() == PRINCIPAL)
            .then_some(())
            .ok_or(Error::NotFound)
    }

    fn snapshot(
        record: ProjectTrustRecord,
        metadata: runne_store::OwnedWorkspaceTrustMetadata,
        root_version: Option<u64>,
    ) -> Snapshot {
        let (status, provenance) = match record.status {
            ProjectTrustStatus::Untrusted => (
                Status::Untrusted,
                if record.managed_deny_mask != 0 {
                    Provenance::Managed
                } else if record.revision == 0 {
                    Provenance::Default
                } else {
                    Provenance::User
                },
            ),
            ProjectTrustStatus::Trusted => (
                Status::Trusted,
                if record.managed_deny_mask != 0 {
                    Provenance::Managed
                } else {
                    Provenance::User
                },
            ),
            ProjectTrustStatus::Managed => (Status::Managed, Provenance::Managed),
        };
        Snapshot {
            project_id: metadata.project_id,
            project_name: metadata.project_name,
            project_version: metadata.project_version,
            workspace_id: metadata.workspace_id,
            workspace_name: metadata.workspace_name,
            workspace_version: metadata.workspace_version,
            status,
            managed_deny_mask: record.managed_deny_mask,
            provenance,
            epoch: record.instance_epoch,
            revision: record.revision,
            root_admission_version: root_version,
        }
    }

    fn get_sync(
        &self,
        principal: ApiPrincipalId,
        project: ProjectId,
        workspace: WorkspaceId,
    ) -> Result<Snapshot, Error> {
        Self::check_principal(&principal)?;
        let trust_project = ProjectTrustProjectId::from_bytes(*project.as_bytes());
        let lease = self
            .trust
            .acquire_control_lease(trust_project)
            .map_err(|_| Error::Unavailable)?;
        let record = lease.record();
        self.store
            .with_owned_workspace_trust_metadata(PRINCIPAL, project, workspace, |metadata| {
                let root = self
                    .roots
                    .read_current_trust_root_version(workspace, metadata.workspace_version)
                    .map_err(|_| ProjectWorkspaceRepositoryError::Unavailable)?;
                Ok(Self::snapshot(record, metadata, root))
            })
            .map_err(map_repo)
    }

    fn decide_sync(
        &self,
        principal: ApiPrincipalId,
        project: ProjectId,
        workspace: WorkspaceId,
        request: ProjectTrustControlRequest,
    ) -> Result<Snapshot, Error> {
        Self::check_principal(&principal)?;
        let trust_project = ProjectTrustProjectId::from_bytes(*project.as_bytes());
        let mut lease = self
            .trust
            .acquire_control_lease(trust_project)
            .map_err(|_| Error::Unavailable)?;
        let current = lease.record();
        self.store
            .with_owned_workspace_trust_metadata(PRINCIPAL, project, workspace, |metadata| {
                let result = (|| {
                    if current.instance_epoch != request.expected_epoch
                        || current.revision != request.expected_revision
                    {
                        return Err(Error::Conflict);
                    }
                    if current.status == ProjectTrustStatus::Managed
                        || current.managed_deny_mask != 0
                    {
                        return Err(Error::ManagedPolicy);
                    }
                    if metadata.project_version != request.expected_project_version
                        || metadata.workspace_version != request.expected_workspace_version
                    {
                        return Err(Error::Conflict);
                    }
                    let trusted = request.decision == Decision::ConfirmProject;
                    if trusted {
                        let expected_root = request
                            .expected_root_admission_version
                            .ok_or(Error::RootUnavailable)?;
                        let observed = self
                            .roots
                            .read_current_trust_root_version(workspace, metadata.workspace_version)
                            .map_err(|_| Error::Unavailable)?
                            .ok_or(Error::RootUnavailable)?;
                        if observed != expected_root {
                            return Err(Error::Conflict);
                        }
                        let committed = self
                            .roots
                            .with_current_trust_root(
                                workspace,
                                metadata.workspace_version,
                                expected_root,
                                |_| {
                                    let record = lease
                                        .decide(true, current.token())
                                        .map_err(map_persistence)?;
                                    Ok(record)
                                },
                            )
                            .map_err(|error| match error {
                                TrustRootDecisionError::Unavailable => Error::RootUnavailable,
                                TrustRootDecisionError::Stale => Error::Conflict,
                                TrustRootDecisionError::Operation(value) => value,
                            })?;
                        Ok(Self::snapshot(committed, metadata, Some(expected_root)))
                    } else {
                        let committed = lease
                            .decide(false, current.token())
                            .map_err(map_persistence)?;
                        Ok(Self::snapshot(committed, metadata, None))
                    }
                })();
                Ok(result)
            })
            .map_err(map_repo)?
    }
}

impl ProjectTrustControlHostPort for TrustControlHost {
    async fn get_project_trust(
        &self,
        principal: ApiPrincipalId,
        project: ProjectId,
        workspace: WorkspaceId,
    ) -> Result<Snapshot, Error> {
        let host = self.clone();
        tokio::task::spawn_blocking(move || host.get_sync(principal, project, workspace))
            .await
            .map_err(|_| Error::Unavailable)?
    }

    async fn decide_project_trust(
        &self,
        principal: ApiPrincipalId,
        project: ProjectId,
        workspace: WorkspaceId,
        request: ProjectTrustControlRequest,
    ) -> Result<Snapshot, Error> {
        let host = self.clone();
        tokio::task::spawn_blocking(move || {
            host.decide_sync(principal, project, workspace, request)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}

#[cfg(test)]
#[path = "trust_control_tests.rs"]
mod tests;

fn map_repo(error: ProjectWorkspaceRepositoryError) -> Error {
    match error {
        ProjectWorkspaceRepositoryError::NotFound | ProjectWorkspaceRepositoryError::Forbidden => {
            Error::NotFound
        }
        ProjectWorkspaceRepositoryError::Conflict => Error::Conflict,
        _ => Error::Unavailable,
    }
}

fn map_persistence(error: TrustPersistenceError) -> Error {
    match error {
        TrustPersistenceError::Conflict { .. } | TrustPersistenceError::ForeignEpoch { .. } => {
            Error::Conflict
        }
        TrustPersistenceError::Unavailable => Error::Unavailable,
    }
}
