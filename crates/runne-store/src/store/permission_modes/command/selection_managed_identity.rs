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
    load_on_connection(store, &reader, scope, principal, authority)
}

pub(in crate::store::permission_modes) fn load_on_connection(
    store: &StoreTransaction,
    connection: &rusqlite::Connection,
    scope: &PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<PermissionModeSelectionManagedIdentity, PermissionModeStoreError> {
    identity::check_scope_authority(store, scope, principal)?;
    if authority.authenticated_principal != principal {
        return Err(PermissionModeStoreError::AuthorityMismatch);
    }
    let workspace = identity::owned_open_workspace(connection, scope)?;
    let row = selection::selection_row(connection, scope)?;
    selection::load(connection, scope, row, workspace, authority)
}

pub(in crate::store) fn current_on_connection(
    store: &StoreTransaction,
    connection: &rusqlite::Connection,
    scope: &PermissionScope,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<
    (
        PermissionModeSelectionManagedIdentity,
        super::super::ClosedRulesManagedIdentityV2,
    ),
    PermissionModeStoreError,
> {
    let selection = load_on_connection(store, connection, scope, &scope.principal_id, authority)?;
    let workspace = identity::owned_open_workspace(connection, scope)?;
    let managed = identity::managed_snapshot(authority, workspace.project_id)?;
    let current = super::super::managed_identity::lease::current(authority, workspace, managed)?;
    Ok((selection, current))
}
