use std::sync::Arc;

use runne_provider::{
    CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority,
};
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
    pub(super) enrollment_authorities: Option<CredentialEnrollmentControlAuthorities>,
}

pub(super) struct CredentialEnrollmentControlAuthorities {
    pub(super) measurements: CredentialEnrollmentMeasurementAuthority,
    pub(super) store: CredentialEnrollmentStoreAuthority,
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
        enrollment_authorities: Some(CredentialEnrollmentControlAuthorities {
            measurements: credentials.measurements,
            store: credentials.enrollment_store_authority,
        }),
    })
}

// fixture-only capability begin
#[cfg(test)]
pub(super) fn fixture(
    connection: ManagedConnection,
    owner: [u8; 16],
    fencing_token: u64,
    credential_id: ProviderCredentialId,
    native: Option<
        Arc<crate::application::workspace_internal::FixtureCredentialVersionStoreFactory>,
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
        enrollment_authorities: None,
    })
}

#[cfg(all(feature = "test-support", not(test)))]
pub(super) fn fixture(
    connection: ManagedConnection,
    _owner: [u8; 16],
    _fencing_token: u64,
    credential_id: ProviderCredentialId,
    adapter: Arc<dyn CanonicalProviderEffect>,
) -> Result<CredentialBoundary, DaemonError> {
    let store = super::fixture_credentials::compose(connection, credential_id)?;
    Ok(CredentialBoundary {
        store,
        readback: None,
        adapter,
        status: ProviderCredentialStatus::Configured,
        enrollment_authorities: None,
    })
}
// fixture-only capability end
