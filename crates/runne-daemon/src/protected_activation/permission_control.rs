use std::sync::{Arc, Mutex};

use runne_api::{
    ApiPrincipalId, PermissionControlContextV1, PermissionControlModeChallengeV1,
    PermissionModeHostErrorV1, PermissionModeNativePendingHostV2,
    PermissionModeNativePendingPageV2, PermissionModeSelectionV1, PermissionNetworkStateV1,
};
use runne_application::{
    local_session::LocalSessionService,
    permission_modes::{PermissionMode, PermissionScope},
    ports::ProjectWorkspaceRepository,
};
use runne_domain::id::{CommandId, WorkspaceId};
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::{
    ProjectWorkspaceStore,
    store::{PermissionModeCeremonyStatusV2, ProtectedNativeLaunchContext, StoreTransaction},
};
pub(crate) fn containment_v1(
    value: runne_application::permission_modes::ContainmentStrategy,
) -> runne_api::PermissionContainmentV1 {
    use runne_application::permission_modes::ContainmentStrategy as Strategy;
    match value {
        Strategy::WorkspaceBoundV1 => runne_api::PermissionContainmentV1::WorkspaceBoundV1,
        Strategy::SameUserCompositeV1 | Strategy::SameUserCompositeV2 => {
            runne_api::PermissionContainmentV1::SameUserCompositeV1
        }
    }
}

pub(crate) fn network_v1(
    value: runne_application::permission_modes::NetworkState,
) -> PermissionNetworkStateV1 {
    match value {
        runne_application::permission_modes::NetworkState::Unavailable => {
            PermissionNetworkStateV1::Unavailable
        }
        runne_application::permission_modes::NetworkState::Brokered => {
            PermissionNetworkStateV1::Brokered
        }
        runne_application::permission_modes::NetworkState::BroadSameUser => {
            PermissionNetworkStateV1::BroadSameUser
        }
    }
}
#[derive(Clone)]
struct CurrentOwner {
    principal: ApiPrincipalId,
    launch: ProtectedNativeLaunchContext,
}

/// Read-only access to pending work owned by the live protected channel.
#[derive(Clone)]
pub(crate) struct PermissionControlHost {
    store: StoreTransaction,
    workspaces: ProjectWorkspaceStore,
    sessions: Arc<Mutex<LocalSessionService>>,
    trust: Option<Arc<ProjectTrustPolicyAuthority>>,
    current: Arc<Mutex<Option<CurrentOwner>>>,
}

impl PermissionControlHost {
    pub(crate) fn new(
        store: StoreTransaction,
        workspaces: ProjectWorkspaceStore,
        sessions: Arc<Mutex<LocalSessionService>>,
        trust: Option<Arc<ProjectTrustPolicyAuthority>>,
    ) -> Self {
        Self {
            store,
            workspaces,
            sessions,
            trust,
            current: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn observe_launch(
        &self,
        owned: &runne_api::ProtectedOwnedLaunchV1,
        keys: &runne_api::ProtectedActivationKeys,
    ) -> Result<(), runne_api::LaunchAuthorityError> {
        let launch = ProtectedNativeLaunchContext::new(
            *owned.launch_authority_id(),
            *owned.desktop_host_instance_id(),
            *owned.daemon_instance_id(),
            owned.launch_generation(),
            keys.permission_control_native_authenticator()
                .native_key_epoch(),
        )
        .and_then(|value| value.with_protected_session_id(*owned.session_id()))
        .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        if !super::permission_dispatch::owner_matches_current_session(
            owned,
            sessions.current_binding(),
        ) {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        let current = CurrentOwner {
            principal: ApiPrincipalId::new(owned.stable().principal_id().to_owned())
                .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?,
            launch,
        };
        *self
            .current
            .lock()
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)? = Some(current);
        Ok(())
    }

    pub(crate) fn store(&self) -> &StoreTransaction {
        &self.store
    }

    pub(crate) fn workspaces(&self) -> &ProjectWorkspaceStore {
        &self.workspaces
    }

    pub(crate) fn trust(&self) -> Option<&Arc<ProjectTrustPolicyAuthority>> {
        self.trust.as_ref()
    }

    pub(crate) fn with_current_launch<T>(
        &self,
        principal: &ApiPrincipalId,
        operation: impl FnOnce(&ProtectedNativeLaunchContext) -> Result<T, PermissionModeHostErrorV1>,
    ) -> Result<T, PermissionModeHostErrorV1> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)?;
        let current = self
            .current
            .lock()
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)?;
        let owner = current
            .as_ref()
            .ok_or(PermissionModeHostErrorV1::NativeAuthorityUnavailable)?;
        if &owner.principal != principal
            || owner.launch.protected_session_id()
                != Some(sessions.current_binding().ephemeral().session_id())
        {
            return Err(PermissionModeHostErrorV1::NativeAuthorityUnavailable);
        }
        operation(&owner.launch)
    }

    pub(crate) fn mode_challenge(
        &self,
        principal: &ApiPrincipalId,
        command_id: CommandId,
    ) -> Result<
        Option<(PermissionControlContextV1, PermissionControlModeChallengeV1)>,
        runne_api::LaunchAuthorityError,
    > {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        let current = self
            .current
            .lock()
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        let Some(owner) = current.clone() else {
            return Ok(None);
        };
        if &owner.principal != principal
            || owner.launch.protected_session_id()
                != Some(sessions.current_binding().ephemeral().session_id())
        {
            return Ok(None);
        }
        let Some(pending) = self
            .store
            .discover_permission_mode_native_pending_command_v2(
                principal,
                &owner.launch,
                command_id,
            )
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?
        else {
            return Ok(None);
        };
        let context = pending
            .context
            .control_context()
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        let workspace_id = pending
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        let scope = PermissionScope {
            runtime_authority_id: self.store.runtime_authority_id().clone(),
            principal_id: principal.clone(),
            workspace_id,
        };
        let Some(PermissionModeCeremonyStatusV2::Pending(issued)) = self
            .store
            .load_permission_mode_confirmation_status_v2(&scope, principal, command_id)
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?
        else {
            return Ok(None);
        };
        let binding = issued.binding();
        let session_id = owner
            .launch
            .protected_session_id()
            .ok_or(runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        if binding.command_id != command_id
            || binding.scope != scope
            || binding.protected_session_id != *session_id
            || binding.public_request_digest.as_bytes()
                != pending.context.public_request_digest.as_slice()
        {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        let workspace = self
            .workspaces
            .get_workspace(principal.as_str(), workspace_id)
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        let mode_expires_at_unix_ms = binding
            .expires_at_unix_ms
            .map(u64::try_from)
            .transpose()
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        let ceremony_expires_at_unix_ms = u64::try_from(binding.challenge_expires_at_unix_ms)
            .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        let requested_mode = match binding.requested_mode {
            PermissionMode::AskAlways => PermissionModeSelectionV1::AskAlways,
            PermissionMode::RiskBased => PermissionModeSelectionV1::RiskBased,
            PermissionMode::FullAccess => PermissionModeSelectionV1::FullAccess,
        };
        let challenge = PermissionControlModeChallengeV1 {
            principal: principal.as_str().to_owned(),
            workspace_id: *workspace_id.as_bytes(),
            workspace_label: workspace.display_name().to_owned(),
            expected_authorization_revision: binding.expected_authorization_revision,
            requested_mode,
            preset_version: binding.preset_version.as_u16(),
            mode_expires_at_unix_ms,
            managed_policy_revision: binding.managed_policy_version,
            managed_policy_digest: *binding.managed_policy_digest.as_bytes(),
            issued_challenge_binding_digest: *binding.challenge_binding_digest.as_bytes(),
            ceremony_expires_at_unix_ms,
            native_warning_version: binding.native_warning_version,
            challenge_id: *issued.challenge_id(),
            nonce: *issued.nonce_for_native_signing(),
        };
        Ok(Some((context, challenge)))
    }

    fn native_pending_sync(
        &self,
        principal: ApiPrincipalId,
        after: Option<CommandId>,
    ) -> Result<PermissionModeNativePendingPageV2, PermissionModeHostErrorV1> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)?;
        let current = self
            .current
            .lock()
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)?;
        let Some(owner) = current.clone() else {
            return Err(PermissionModeHostErrorV1::NativeAuthorityUnavailable);
        };
        if owner.principal != principal
            || owner.launch.protected_session_id()
                != Some(sessions.current_binding().ephemeral().session_id())
        {
            return Err(PermissionModeHostErrorV1::NativeAuthorityUnavailable);
        }
        self.store
            .discover_permission_mode_native_pending_v2(&principal, &owner.launch, after)
            .map_err(|_| PermissionModeHostErrorV1::Unavailable)
    }
}

impl PermissionModeNativePendingHostV2 for PermissionControlHost {
    fn native_pending(
        &self,
        principal: ApiPrincipalId,
        after: Option<CommandId>,
    ) -> impl std::future::Future<
        Output = Result<PermissionModeNativePendingPageV2, PermissionModeHostErrorV1>,
    > + Send {
        let host = self.clone();
        async move {
            tokio::task::spawn_blocking(move || host.native_pending_sync(principal, after))
                .await
                .map_err(|_| PermissionModeHostErrorV1::Unavailable)?
        }
    }
}
include!("permission_control/commit.rs");
