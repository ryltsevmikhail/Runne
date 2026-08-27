use super::composition::PROVIDER_POLICY_V1_LEASE_SECONDS;
use crate::application::workspace_internal::LoopbackCredentialVersionStoreFactory;
use crate::error::DaemonError;
#[cfg(test)]
use runne_provider::NativeCredentialAuthority;
use runne_provider::{
    CredentialAuthorityPair, CredentialLease, ProviderCredentialVersionStore, ProviderId,
    RevokeCredentialVersion,
};
#[cfg(test)]
use runne_secure_store::ProviderCredentialStore;
use runne_secure_store::{
    NativeProviderCredentialStore, NativeProviderCredentialVersionStore,
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialStatus,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::ManagedConnection;
use std::sync::Arc;
#[cfg(test)]
include!("credential_versions/source.rs");
const FIXTURE_SOURCE_REVISION: [u8; 16] = [0xF1; 16];

#[derive(Clone, Copy)]
struct ProvisionActivation {
    owner: [u8; 16],
    fencing_token: u64,
    now: i64,
}

pub(super) struct ComposedCredentialLifecycle {
    pub(super) store: Arc<SqliteProviderCredentialLifecycleStore>,
    #[cfg(test)]
    pub(super) native_authority: NativeCredentialAuthority,
}

pub(super) fn compose_credential_lifecycle(
    connection: ManagedConnection,
    owner: [u8; 16],
    fencing_token: u64,
    credential_id: ProviderCredentialId,
    fixture: bool,
    fixture_native: Option<Arc<LoopbackCredentialVersionStoreFactory>>,
) -> Result<ComposedCredentialLifecycle, DaemonError> {
    let (lifecycle_authority, native_authority) = CredentialAuthorityPair::new().split();
    let store = Arc::new(
        SqliteProviderCredentialLifecycleStore::open_with_connection_and_authority(
            connection,
            lifecycle_authority,
        )
        .map_err(|_| unavailable())?,
    );
    let native = fixture_native.map_or_else(
        || {
            Arc::new(NativeProviderCredentialStore::new_versioned(
                native_authority.clone(),
            )) as Arc<dyn NativeProviderCredentialVersionStore>
        },
        |factory| factory(native_authority.clone()),
    );
    let now = chrono::Utc::now().timestamp();
    let provider = ProviderId::new(credential_id.account()).map_err(|_| unavailable())?;
    let activation = ProvisionActivation {
        owner,
        fencing_token,
        now,
    };
    resolve_pending_provision(
        store.as_ref(),
        native.as_ref(),
        &provider,
        activation,
        credential_id,
        fixture,
    )?;
    reconcile_native(store.as_ref(), native.as_ref(), now)?;
    if store
        .authorize_active(&provider, owner, fencing_token, now)
        .is_err()
    {
        rotate_stale_active(
            store.as_ref(),
            native.as_ref(),
            &provider,
            activation.fencing_token,
            activation.now,
        )?;
        provision_active(
            store.as_ref(),
            native.as_ref(),
            &provider,
            activation,
            credential_id,
            fixture,
        )?;
    }
    store
        .authorize_active(&provider, owner, fencing_token, now)
        .map_err(|_| unavailable())?;
    Ok(ComposedCredentialLifecycle {
        store,
        #[cfg(test)]
        native_authority,
    })
}

fn resolve_pending_provision(
    store: &SqliteProviderCredentialLifecycleStore,
    native: &dyn NativeProviderCredentialVersionStore,
    provider: &ProviderId,
    activation: ProvisionActivation,
    credential_id: ProviderCredentialId,
    fixture: bool,
) -> Result<(), DaemonError> {
    finish_completed_provision(store, provider)?;
    if store
        .pending_provision(provider)
        .map_err(|_| unavailable())?
        .is_some()
    {
        provision_active(store, native, provider, activation, credential_id, fixture)?;
    }
    Ok(())
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
    activation: ProvisionActivation,
    _credential_id: ProviderCredentialId,
    fixture: bool,
) -> Result<(), DaemonError> {
    if !fixture {
        return Err(unavailable());
    }
    provision_active_with_material(
        store,
        native,
        provider,
        activation,
        FIXTURE_SOURCE_REVISION,
        None,
    )
}

fn provision_active_with_material(
    store: &SqliteProviderCredentialLifecycleStore,
    native: &dyn NativeProviderCredentialVersionStore,
    provider: &ProviderId,
    activation: ProvisionActivation,
    source_revision: [u8; 16],
    native_input: Option<(&ProviderCredentialMaterial, &ProviderCredentialAccessPolicy)>,
) -> Result<(), DaemonError> {
    let source = store
        .provision_source(source_revision)
        .map_err(|_| unavailable())?;
    let provision = match store
        .pending_provision(provider)
        .map_err(|_| unavailable())?
    {
        Some(provision) => store
            .begin_provision(provider, *provision.operation_id(), &source)
            .map_err(|_| unavailable())?,
        None => store
            .begin_provision(provider, *uuid::Uuid::now_v7().as_bytes(), &source)
            .map_err(|_| unavailable())?,
    };
    let reference = provision.version_ref().clone();
    if let Some((material, access)) = native_input {
        if !provision.native_created() {
            native
                .create_version(
                    store
                        .claim_native_create(&provision)
                        .map_err(|_| unavailable())?,
                    material,
                    access,
                )
                .map_err(|_| unavailable())?;
        }
        if native
            .version_status(&reference, access)
            .map_err(|_| unavailable())?
            != ProviderCredentialStatus::Configured
        {
            return Err(unavailable());
        }
    }
    let provision = store
        .mark_native_created(&provision)
        .map_err(|_| unavailable())?;
    let expires_at = activation
        .now
        .checked_add(i64::try_from(PROVIDER_POLICY_V1_LEASE_SECONDS).unwrap_or(i64::MAX))
        .ok_or_else(unavailable)?;
    store
        .activate(
            CredentialLease::new(
                reference,
                activation.owner,
                expires_at,
                activation.fencing_token,
            )
            .map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
    store
        .complete_provision(&provision)
        .map_err(|_| unavailable())?;
    Ok(())
}

fn finish_completed_provision(
    store: &SqliteProviderCredentialLifecycleStore,
    provider: &ProviderId,
) -> Result<(), DaemonError> {
    let Some(provision) = store
        .pending_provision(provider)
        .map_err(|_| unavailable())?
    else {
        return Ok(());
    };
    let Some(active) = store.active_lease(provider).map_err(|_| unavailable())? else {
        return Ok(());
    };
    if !provision.native_created() || active.version_ref() != provision.version_ref() {
        return Err(unavailable());
    }
    store
        .complete_provision(&provision)
        .map_err(|_| unavailable())
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

fn unavailable() -> DaemonError {
    DaemonError::Bootstrap("provider credential lifecycle unavailable".into())
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::fixture_native;
