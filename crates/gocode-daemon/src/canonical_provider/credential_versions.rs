use std::sync::Arc;

use gocode_provider::{
    CredentialAuthorityPair, CredentialLease, NativeCredentialAuthority, PrepareCredentialVersion,
    ProviderCredentialVersionStore, ProviderId, RevokeCredentialVersion,
};
use gocode_secure_store::{
    NativeProviderCredentialStore, NativeProviderCredentialVersionStore,
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialStore,
};
use gocode_store::provider::SqliteProviderCredentialLifecycleStore;
use gocode_store::schema::ManagedConnection;

use super::composition::PROVIDER_POLICY_V1_LEASE_SECONDS;
use crate::error::DaemonError;

pub(super) struct ComposedCredentialLifecycle {
    pub(super) store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) native_authority: NativeCredentialAuthority,
}

pub(super) fn compose_credential_lifecycle(
    connection: ManagedConnection,
    owner: [u8; 16],
    fencing_token: u64,
    fixture: bool,
) -> Result<ComposedCredentialLifecycle, DaemonError> {
    let (lifecycle_authority, native_authority) = CredentialAuthorityPair::new().split();
    let store = Arc::new(
        SqliteProviderCredentialLifecycleStore::open_with_connection_and_authority(
            connection,
            lifecycle_authority,
        )
        .map_err(|_| unavailable())?,
    );
    let native = native_version_store(native_authority.clone(), fixture);
    let now = chrono::Utc::now().timestamp();
    reconcile_native(store.as_ref(), native.as_ref(), now)?;
    let provider =
        ProviderId::new(ProviderCredentialId::OpenAi.account()).map_err(|_| unavailable())?;
    if store
        .authorize_active(&provider, owner, fencing_token, now)
        .is_err()
    {
        rotate_stale_active(
            store.as_ref(),
            native.as_ref(),
            &provider,
            fencing_token,
            now,
        )?;
        provision_active(
            store.as_ref(),
            native.as_ref(),
            &provider,
            owner,
            fencing_token,
            now,
            fixture,
        )?;
    }
    store
        .authorize_active(&provider, owner, fencing_token, now)
        .map_err(|_| unavailable())?;
    Ok(ComposedCredentialLifecycle {
        store,
        native_authority,
    })
}

fn native_version_store(
    authority: NativeCredentialAuthority,
    fixture: bool,
) -> Arc<dyn NativeProviderCredentialVersionStore> {
    #[cfg(test)]
    if fixture {
        return tests::fixture_native(authority);
    }
    let _ = fixture;
    Arc::new(NativeProviderCredentialStore::new_versioned(authority))
}

fn rotate_stale_active(
    store: &SqliteProviderCredentialLifecycleStore,
    native: &dyn NativeProviderCredentialVersionStore,
    provider: &ProviderId,
    fencing_token: u64,
    now: i64,
) -> Result<(), DaemonError> {
    if let Some(active) = store.active_lease(provider).map_err(|_| unavailable())? {
        if active.fencing_token() >= fencing_token {
            return Err(unavailable());
        }
        store
            .revoke_and_fence(
                RevokeCredentialVersion::new(active.version_ref().clone(), active.fencing_token())
                    .map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?;
        reconcile_native(store, native, now)?;
    }
    Ok(())
}

fn provision_active(
    store: &SqliteProviderCredentialLifecycleStore,
    native: &dyn NativeProviderCredentialVersionStore,
    provider: &ProviderId,
    owner: [u8; 16],
    fencing_token: u64,
    now: i64,
    fixture: bool,
) -> Result<(), DaemonError> {
    let reference = store
        .next_version_ref(provider)
        .map_err(|_| unavailable())?;
    store
        .create_prepared(PrepareCredentialVersion::new(reference.clone()))
        .map_err(|_| unavailable())?;
    if !fixture {
        let access = credential_access_policy()?;
        let legacy = NativeProviderCredentialStore::new()
            .load_provider_credential(ProviderCredentialId::OpenAi, &access)
            .map_err(|_| unavailable())?;
        native
            .create_version(reference.clone(), &legacy, &access)
            .map_err(|_| unavailable())?;
    }
    let expires_at = now
        .checked_add(i64::try_from(PROVIDER_POLICY_V1_LEASE_SECONDS).unwrap_or(i64::MAX))
        .ok_or_else(unavailable)?;
    store
        .activate(
            CredentialLease::new(reference, owner, expires_at, fencing_token)
                .map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
    Ok(())
}

pub(super) fn reconcile_native(
    store: &SqliteProviderCredentialLifecycleStore,
    native: &dyn NativeProviderCredentialVersionStore,
    now: i64,
) -> Result<(), DaemonError> {
    for claim in store
        .reconcile(now)
        .map_err(|_| unavailable())?
        .into_native_deletions()
    {
        let proof = native.delete_version(claim).map_err(|_| unavailable())?;
        store
            .complete_native_delete(proof)
            .map_err(|_| unavailable())?;
    }
    Ok(())
}

fn credential_access_policy() -> Result<ProviderCredentialAccessPolicy, DaemonError> {
    let reader = std::fs::canonicalize(std::env::current_exe().map_err(|_| unavailable())?)
        .map_err(|_| unavailable())?;
    let writer = reader.parent().ok_or_else(unavailable)?.join("gocode");
    ProviderCredentialAccessPolicy::new(&writer, &reader).map_err(|_| unavailable())
}

fn unavailable() -> DaemonError {
    DaemonError::Bootstrap("provider credential lifecycle unavailable".into())
}

#[cfg(test)]
mod tests;
