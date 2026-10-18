use std::{future::Future, sync::Arc};

use crate::application::root_handle_admission::RootAdmissionGateway;
use runne_api::{
    ApiPrincipalId, ApprovalQueryContext, ApprovalQueryHostPort, PermissionModeCommandStatusV2,
    PermissionModeControlHostV2, PermissionModeHostErrorV1, PermissionModeStatusV1,
    ValidatedPermissionModeChangeV1,
};
use runne_application::{
    permission_modes::{PermissionScope, PresetVersion},
    ports::{EventStore, ProjectWorkspaceRepository},
    project_trust::{
        PermissionMode as TrustMode, ProjectTrustProjectId, SourceAdmissionRequest, SourceChannel,
    },
};
use runne_domain::id::{CommandId, WorkspaceId};
use runne_domain::task_run::TaskRun;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::store::{NativeModeConfirmationRequestV2, PermissionModeAuthorityContext};

use crate::protected_activation::PermissionControlHost;

#[derive(Clone)]
pub(super) struct PermissionModeHttpHost {
    control: PermissionControlHost,
    trust: Option<Arc<ProjectTrustPolicyAuthority>>,
    root: RootAdmissionGateway,
}

impl PermissionModeHttpHost {
    pub(super) fn new(
        control: PermissionControlHost,
        trust: Option<Arc<ProjectTrustPolicyAuthority>>,
        root: RootAdmissionGateway,
    ) -> Self {
        Self {
            control,
            trust,
            root,
        }
    }

    fn request_sync(
        &self,
        principal: ApiPrincipalId,
        request: ValidatedPermissionModeChangeV1,
    ) -> Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1> {
        self.control.with_current_launch(&principal, |launch| {
            let workspace = self
                .control
                .workspaces()
                .get_workspace(principal.as_str(), request.workspace_id())
                .map_err(|_| PermissionModeHostErrorV1::NotFound)?;
            if !workspace.open_state() {
                return Err(PermissionModeHostErrorV1::NotFound);
            }
            let project = ProjectTrustProjectId::from_bytes(*workspace.project_id().as_bytes());
            let trust = self
                .trust
                .as_ref()
                .ok_or(PermissionModeHostErrorV1::Unavailable)?;
            let lease = trust
                .acquire_effect_lease(
                    project,
                    SourceAdmissionRequest {
                        channel: SourceChannel::FilesList,
                        path: None,
                        observed_token: None,
                        permission_mode: TrustMode::Ask,
                    },
                )
                .map_err(super::trust_error)?;
            let scope = self.scope(principal.clone(), request.workspace_id());
            let input = NativeModeConfirmationRequestV2 {
                command_id: request.command_id(),
                idempotency_key: request.idempotency_key().clone(),
                scope: scope.clone(),
                expected_authorization_revision: request.expected_authorization_revision(),
                requested_mode: super::permission_projection::mode_app(request.requested_mode()),
                preset_version: PresetVersion::V1,
                expires_at_unix_ms: request.expires_at_unix_ms(),
            };
            let authority = PermissionModeAuthorityContext::new(
                &principal,
                project,
                lease.as_ref(),
                Some(launch),
            );
            let status = self
                .control
                .store()
                .begin_permission_mode_confirmation_v2(input, &authority)
                .map_err(super::permission_projection::store_error)?;
            super::permission_projection::ceremony_status(status, request.command_id())
        })
    }

    fn command_sync(
        &self,
        principal: ApiPrincipalId,
        workspace: WorkspaceId,
        command_id: CommandId,
    ) -> Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1> {
        let scope = self.scope(principal.clone(), workspace);
        let status = self
            .control
            .store()
            .load_permission_mode_confirmation_status_v2(&scope, &principal, command_id)
            .map_err(super::permission_projection::store_error)?
            .ok_or(PermissionModeHostErrorV1::NotFound)?;
        super::permission_projection::ceremony_status(status, command_id)
    }

    fn scope(&self, principal: ApiPrincipalId, workspace: WorkspaceId) -> PermissionScope {
        PermissionScope {
            runtime_authority_id: self.control.store().runtime_authority_id().clone(),
            principal_id: principal,
            workspace_id: workspace,
        }
    }
}

impl PermissionModeControlHostV2 for PermissionModeHttpHost {
    fn status(
        &self,
        principal: ApiPrincipalId,
        workspace_id: WorkspaceId,
    ) -> impl Future<Output = Result<PermissionModeStatusV1, PermissionModeHostErrorV1>> + Send
    {
        let host = self.clone();
        async move {
            let status_host = host.clone();
            let status_principal = principal.clone();
            let mut status = tokio::task::spawn_blocking(move || {
                super::permission_projection::status_sync(
                    &status_host.control,
                    &status_host.root,
                    status_principal,
                    workspace_id,
                )
            })
            .await
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)??;
            let approvals =
                runne_store::ProjectWorkspaceStore::from_store(host.control.store().clone())
                    .list_pending_approvals(ApprovalQueryContext { principal })
                    .await
                    .map_err(|_| PermissionModeHostErrorV1::Unavailable)?;
            let store = host.control.store().clone();
            status.pending_approval_ids = tokio::task::spawn_blocking(move || {
                crate::application::permission_projection::pending_ids_for_workspace(
                    approvals,
                    workspace_id,
                    |task_run_id| {
                        let stream = store
                            .load_task_run(task_run_id)
                            .map_err(|_| crate::application::permission_projection::PendingApprovalScopeUnavailable)?;
                        let task = TaskRun::replay(&stream.events)
                            .map_err(|_| crate::application::permission_projection::PendingApprovalScopeUnavailable)?;
                        Ok(task.snapshot_v1().workspace_id())
                    },
                )
            })
            .await
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)?
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)?;
            Ok(status)
        }
    }

    fn request_mode_change(
        &self,
        principal: ApiPrincipalId,
        request: ValidatedPermissionModeChangeV1,
    ) -> impl Future<Output = Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1>> + Send
    {
        let host = self.clone();
        async move {
            tokio::task::spawn_blocking(move || host.request_sync(principal, request))
                .await
                .map_err(|_| PermissionModeHostErrorV1::Unavailable)?
        }
    }

    fn command_status(
        &self,
        principal: ApiPrincipalId,
        workspace_id: WorkspaceId,
        command_id: CommandId,
    ) -> impl Future<Output = Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1>> + Send
    {
        let host = self.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                host.command_sync(principal, workspace_id, command_id)
            })
            .await
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)?
        }
    }
}
