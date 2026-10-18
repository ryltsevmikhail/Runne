use runne_application::permission_modes::PermissionScope;

use super::super::{
    identity,
    managed_identity::selection,
    model::{
        PermissionModeAuthorityContext, PermissionModeSelectionManagedIdentity,
        PermissionModeStoreError,
    },
};
use crate::store::StoreTransaction;

pub(super) fn load(
    store: &StoreTransaction,
    scope: &PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<PermissionModeSelectionManagedIdentity, PermissionModeStoreError> {
    identity::check_scope_authority(store, scope, principal)?;
    if authority.authenticated_principal != principal {
        return Err(PermissionModeStoreError::AuthorityMismatch);
    }
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let workspace = identity::owned_open_workspace(&reader, scope)?;
    let row = selection::selection_row(&reader, scope)?;
    selection::load(&reader, scope, row, workspace, authority)
}
