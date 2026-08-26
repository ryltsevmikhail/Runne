use std::sync::Arc;

use runne_secure_store::{
    ProviderCredentialId, ProviderCredentialReadback, ProviderCredentialStatus,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::ManagedConnection;

use super::{CanonicalProviderEffect, ProviderEffectFactory, credential_access_policy};
use crate::error::DaemonError;

pub(super) struct CredentialBoundary {
    pub(super) store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) readback: Option<Arc<dyn ProviderCredentialReadback>>,
    pub(super) adapter: Arc<dyn CanonicalProviderEffect>,
    pub(super) status: ProviderCredentialStatus,
}

pub(super) fn production(
    connection: ManagedConnection,
    credential_id: ProviderCredentialId,
    adapter_factory: &ProviderEffectFactory,
) -> Result<CredentialBoundary, DaemonError> {
    let credentials = super::super::credential_reader::compose(
        connection,
        credential_access_policy(credential_id)?,
    )?;
    let adapter = adapter_factory(Arc::clone(&credentials.dispatch))?;
    Ok(CredentialBoundary {
        store: credentials.store,
        readback: Some(credentials.readback),
        adapter,
        status: ProviderCredentialStatus::Missing,
    })
}

// fixture-only capability begin
#[cfg(any(test, feature = "test-support"))]
pub(super) fn fixture(
    connection: ManagedConnection,
    owner: [u8; 16],
    fencing_token: u64,
    credential_id: ProviderCredentialId,
    native: Option<
        Arc<crate::application::workspace_internal::LoopbackCredentialVersionStoreFactory>,
    >,
    adapter: Arc<dyn CanonicalProviderEffect>,
) -> Result<CredentialBoundary, DaemonError> {
    let credentials = super::super::credential_versions::compose_credential_lifecycle(
        connection,
        owner,
        fencing_token,
        credential_id,
        true,
        native,
    )?;
    Ok(CredentialBoundary {
        store: credentials.store,
        readback: None,
        adapter,
        status: ProviderCredentialStatus::Configured,
    })
}
// fixture-only capability end
