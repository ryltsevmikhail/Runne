mod commit;
mod commit_v2;
pub(super) mod readback_v2;
mod receipt;
mod selection;
mod selection_managed_identity;
pub(in crate::store) use selection_managed_identity::current_on_connection;

use runne_application::permission_modes::{
    PermissionModeChangeReceipt, PermissionModeHistoryProjection, SetPermissionModeCommand,
};

use super::{PermissionModeAuthorityContext, model::*};
use crate::store::StoreTransaction;

pub(super) fn load_selection(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
) -> Result<runne_application::permission_modes::ModeSelection, PermissionModeStoreError> {
    selection::load(store, scope, principal)
}

pub(super) fn load_selection_snapshot(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
) -> Result<super::PermissionModeSelectionSnapshot, PermissionModeStoreError> {
    selection::load_snapshot(store, scope, principal)
}

pub(super) fn load_selection_with_managed_identity(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<PermissionModeSelectionManagedIdentity, PermissionModeStoreError> {
    selection_managed_identity::load(store, scope, principal, authority)
}

pub(super) fn commit(
    store: &StoreTransaction,
    command: SetPermissionModeCommand,
    authority: &PermissionModeAuthorityContext<'_>,
    history: PermissionModeHistoryProjection,
) -> Result<PermissionModeChangeReceipt, PermissionModeStoreError> {
    commit::commit(store, command, authority, history)
}

pub(super) fn begin_confirmation_v2(
    store: &StoreTransaction,
    request: super::NativeModeConfirmationRequestV2,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<super::PermissionModeCeremonyStatusV2, PermissionModeStoreError> {
    super::ceremony_v2::begin(store, request, authority)
}

pub(super) fn load_confirmation_status_v2(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    command_id: runne_domain::id::CommandId,
) -> Result<Option<super::PermissionModeCeremonyStatusV2>, PermissionModeStoreError> {
    readback_v2::load_status(store, scope, principal, command_id)
}

pub(super) fn cancel_confirmation_v2(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    command_id: runne_domain::id::CommandId,
) -> Result<Option<super::PermissionModeCeremonyStatusV2>, PermissionModeStoreError> {
    readback_v2::cancel(store, scope, principal, command_id)
}

pub(super) fn commit_confirmed_v2(
    store: &StoreTransaction,
    command: SetPermissionModeCommand,
    confirmation: runne_application::permission_modes::VerifiedNativeModeConfirmationV2,
    authority: &PermissionModeAuthorityContext<'_>,
    history: PermissionModeHistoryProjection,
) -> Result<PermissionModeChangeReceipt, PermissionModeStoreError> {
    commit_v2::commit(store, command, confirmation, authority, history)
}
