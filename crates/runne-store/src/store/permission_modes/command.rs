mod commit;
mod receipt;
mod selection;

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

pub(super) fn commit(
    store: &StoreTransaction,
    command: SetPermissionModeCommand,
    authority: &PermissionModeAuthorityContext<'_>,
    history: PermissionModeHistoryProjection,
) -> Result<PermissionModeChangeReceipt, PermissionModeStoreError> {
    commit::commit(store, command, authority, history)
}
