use runne_api::{
    ApiPrincipalId, PermissionEffectiveStateV1, PermissionModeChangeReceiptV1,
    PermissionModeCommandStatusV2, PermissionModeHistoryV1, PermissionModeHostErrorV1,
    PermissionModeStatusV1, PermissionModeV1, PermissionNetworkStateV1,
};
use runne_application::permission_modes::{
    EffectiveModeHistoryState, ModeSelection, NetworkState, PermissionMode,
    PermissionModeHistoryProjection, PermissionScope, PresetVersion,
};
use runne_domain::id::{CommandId, IdempotencyKey, IntegrityDigest, WorkspaceId};
use runne_store::store::{
    PermissionModeCeremonyStatusV2, PermissionModeStoreError, StoreTransaction,
};

use crate::{
    application::{permission_projection, root_handle_admission::RootAdmissionGateway},
    protected_activation::PermissionControlHost,
};

pub(super) fn status_sync(
    control: &PermissionControlHost,
    root: &RootAdmissionGateway,
    principal: ApiPrincipalId,
    workspace: WorkspaceId,
) -> Result<PermissionModeStatusV1, PermissionModeHostErrorV1> {
    let scope = permission_scope(control.store(), principal.clone(), workspace);
    let snapshot = control
        .store()
        .load_permission_mode_selection_snapshot(&scope, &principal)
        .map_err(store_error)?;
    let projection = permission_projection::current_projection(
        permission_projection::ProjectionMetadata {
            selection: snapshot.selection.clone(),
            managed_policy_version: snapshot.managed_policy_version,
        },
        || match control.with_current_launch(&principal, |launch| {
            Ok(permission_projection::observe_current_target(
                control.store(),
                control.workspaces(),
                root,
                &principal,
                workspace,
                launch,
                &permission_projection::ProjectionTarget::Current {
                    selection: snapshot.selection.clone(),
                    managed_policy_version: snapshot.managed_policy_version,
                },
            ))
        }) {
            Ok(observation) => observation,
            Err(_) => Err(runne_application::permission_modes::NotReadyReason::NativeContainment),
        },
    );
    Ok(PermissionModeStatusV1 {
        selected_mode: mode_v1(projection.selected_mode),
        effective: effective_v1(projection.history_snapshot().effective)?,
        authorization_revision: projection.authorization_revision,
        preset_version: preset_v1(projection.preset_version)?,
        managed_policy_version: projection.managed_policy_version,
        pending_approval_ids: Vec::new(),
        containment: projection
            .containment
            .map(crate::protected_activation::containment_v1),
        network_state: crate::protected_activation::network_v1(projection.network_state),
        expires_at_unix_ms: projection.expires_at_unix_ms,
    })
}

fn permission_scope(
    store: &StoreTransaction,
    principal: ApiPrincipalId,
    workspace_id: WorkspaceId,
) -> PermissionScope {
    PermissionScope {
        runtime_authority_id: store.runtime_authority_id().clone(),
        principal_id: principal,
        workspace_id,
    }
}

pub(super) fn ceremony_status(
    status: PermissionModeCeremonyStatusV2,
    command_id: CommandId,
) -> Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1> {
    Ok(match status {
        PermissionModeCeremonyStatusV2::Pending(issued) => {
            PermissionModeCommandStatusV2::PendingNativeConfirmation {
                command_id: issued.binding().command_id,
                expires_at_unix_ms: issued.binding().challenge_expires_at_unix_ms,
            }
        }
        PermissionModeCeremonyStatusV2::Committed(receipt) => {
            PermissionModeCommandStatusV2::Committed {
                receipt: receipt_v1(
                    receipt.command_id,
                    &receipt.idempotency_key,
                    receipt.intent_digest,
                    &receipt.selection,
                    receipt.projection,
                )?,
            }
        }
        PermissionModeCeremonyStatusV2::Cancelled => {
            PermissionModeCommandStatusV2::Cancelled { command_id }
        }
        PermissionModeCeremonyStatusV2::Expired => {
            PermissionModeCommandStatusV2::Expired { command_id }
        }
        PermissionModeCeremonyStatusV2::Invalidated => {
            PermissionModeCommandStatusV2::Invalidated { command_id }
        }
    })
}

pub(super) fn mode_app(value: PermissionModeV1) -> PermissionMode {
    match value {
        PermissionModeV1::AskAlways => PermissionMode::AskAlways,
        PermissionModeV1::RiskBased => PermissionMode::RiskBased,
        PermissionModeV1::FullAccess => PermissionMode::FullAccess,
    }
}

pub(super) fn mode_v1(value: PermissionMode) -> PermissionModeV1 {
    match value {
        PermissionMode::AskAlways => PermissionModeV1::AskAlways,
        PermissionMode::RiskBased => PermissionModeV1::RiskBased,
        PermissionMode::FullAccess => PermissionModeV1::FullAccess,
    }
}

pub(super) fn preset_v1(
    value: PresetVersion,
) -> Result<runne_api::PermissionPresetVersionV1, PermissionModeHostErrorV1> {
    runne_api::PermissionPresetVersionV1::from_u16(value.as_u16())
        .ok_or(PermissionModeHostErrorV1::UnsupportedPresetVersion)
}

pub(super) fn effective_v1(
    state: EffectiveModeHistoryState,
) -> Result<PermissionEffectiveStateV1, PermissionModeHostErrorV1> {
    use runne_api::{
        PermissionEffectiveStateV1 as Effective, PermissionModeNotReadyReasonV1 as Reason,
    };
    use runne_application::permission_modes::EffectiveModeHistoryState as State;
    Ok(match state {
        State::NotReady(reason) => Effective::NotReady {
            reason: match reason {
                runne_application::permission_modes::NotReadyReason::NativeContainment => {
                    Reason::NativeContainment
                }
                runne_application::permission_modes::NotReadyReason::CompositePolicyUnenforceable => {
                    Reason::CompositePolicyUnenforceable
                }
                runne_application::permission_modes::NotReadyReason::PresetUnavailable => {
                    Reason::PresetUnavailable
                }
            },
        },
        State::Ready {
            mode,
            preset_version,
            scope_digest,
            containment,
        } => Effective::Ready {
            mode: mode_v1(mode),
            preset_version: preset_v1(preset_version)?,
            scope_digest: IntegrityDigest::from_bytes(*scope_digest.as_bytes()),
            containment: crate::protected_activation::containment_v1(containment),
        },
    })
}

fn receipt_v1(
    command_id: CommandId,
    idempotency_key: &IdempotencyKey,
    intent_digest: IntegrityDigest,
    selection: &ModeSelection,
    projection: PermissionModeHistoryProjection,
) -> Result<PermissionModeChangeReceiptV1, PermissionModeHostErrorV1> {
    let history = PermissionModeHistoryV1 {
        selected_mode: mode_v1(projection.selected_mode),
        effective: effective_v1(projection.effective)?,
        authorization_revision: projection.authorization_revision,
        preset_version: preset_v1(projection.preset_version)?,
        managed_policy_version: projection.managed_policy_version,
        containment: projection
            .containment
            .map(crate::protected_activation::containment_v1),
        network_state: network_v1(projection.network_state),
        expires_at_unix_ms: projection.expires_at_unix_ms,
    };
    Ok(PermissionModeChangeReceiptV1 {
        command_id,
        idempotency_key: idempotency_key.as_str().to_owned(),
        intent_digest,
        authorization_revision: selection.authorization_revision,
        selected_mode: mode_v1(selection.selected_mode),
        history,
    })
}

pub(super) fn network_v1(value: NetworkState) -> PermissionNetworkStateV1 {
    match value {
        NetworkState::Unavailable => PermissionNetworkStateV1::Unavailable,
        NetworkState::Brokered => PermissionNetworkStateV1::Brokered,
        NetworkState::BroadSameUser => PermissionNetworkStateV1::BroadSameUser,
    }
}

pub(super) fn trust_error(
    value: runne_application::project_trust::TrustAdmissionError,
) -> PermissionModeHostErrorV1 {
    match value {
        runne_application::project_trust::TrustAdmissionError::DeniedByPolicy { .. } => {
            PermissionModeHostErrorV1::PolicyDenied
        }
        runne_application::project_trust::TrustAdmissionError::AuthorityUnavailable => {
            PermissionModeHostErrorV1::Unavailable
        }
        _ => PermissionModeHostErrorV1::Conflict,
    }
}

pub(super) fn store_error(value: PermissionModeStoreError) -> PermissionModeHostErrorV1 {
    use runne_application::permission_modes::PermissionModeError as Error;
    match value {
        PermissionModeStoreError::ScopeUnavailable
        | PermissionModeStoreError::AuthorityMismatch => PermissionModeHostErrorV1::NotFound,
        PermissionModeStoreError::ManagedPolicyStale => PermissionModeHostErrorV1::Conflict,
        PermissionModeStoreError::ReauthenticationUnavailable
        | PermissionModeStoreError::Command(Error::ReauthenticationRequired) => {
            PermissionModeHostErrorV1::NativeAuthorityUnavailable
        }
        PermissionModeStoreError::Command(Error::StaleRevision) => {
            PermissionModeHostErrorV1::StaleRevision
        }
        PermissionModeStoreError::Command(Error::IdempotencyConflict) => {
            PermissionModeHostErrorV1::IdempotencyConflict
        }
        PermissionModeStoreError::Command(Error::PolicyDenied) => {
            PermissionModeHostErrorV1::PolicyDenied
        }
        PermissionModeStoreError::Command(Error::Expired) => PermissionModeHostErrorV1::Expired,
        PermissionModeStoreError::Command(Error::Cancelled) => PermissionModeHostErrorV1::Cancelled,
        PermissionModeStoreError::Command(Error::ReconciliationRequired) => {
            PermissionModeHostErrorV1::ReconciliationRequired
        }
        PermissionModeStoreError::Command(Error::CompositePolicyUnenforceable) => {
            PermissionModeHostErrorV1::CompositePolicyUnenforceable
        }
        PermissionModeStoreError::Command(Error::UnsupportedPresetVersion) => {
            PermissionModeHostErrorV1::UnsupportedPresetVersion
        }
        PermissionModeStoreError::Command(_)
        | PermissionModeStoreError::Unavailable
        | PermissionModeStoreError::CorruptData => PermissionModeHostErrorV1::Unavailable,
    }
}
