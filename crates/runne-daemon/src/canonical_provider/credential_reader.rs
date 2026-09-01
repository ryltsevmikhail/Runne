use std::sync::Arc;

use runne_provider::{
    CredentialEnrollmentAuthorityPair, CredentialEnrollmentMeasurementAuthority,
    CredentialEnrollmentStoreAuthority,
};
use runne_secure_store::{
    NativeProviderCredentialReaders, ProviderCredentialAccessPolicy,
    ProviderCredentialDispatchMaterializer, ProviderCredentialReadback,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::ManagedConnection;

use crate::error::DaemonError;

pub(super) struct ComposedCredentialReaders {
    pub(super) store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) readback: Arc<dyn ProviderCredentialReadback>,
    pub(super) dispatch: Arc<dyn ProviderCredentialDispatchMaterializer>,
    pub(super) measurements: CredentialEnrollmentMeasurementAuthority,
    pub(super) enrollment_store_authority: CredentialEnrollmentStoreAuthority,
}

pub(super) fn compose(
    connection: ManagedConnection,
    access: ProviderCredentialAccessPolicy,
) -> Result<ComposedCredentialReaders, DaemonError> {
    let (lifecycle_authority, readback, dispatch, _) =
        NativeProviderCredentialReaders::new(access).into_parts();
    let (enrollment_store_authority, measurements) =
        CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
        connection,
        lifecycle_authority,
        enrollment_store_authority.clone(),
    )
    .map_err(|_| DaemonError::Bootstrap("provider credential lifecycle unavailable".into()))?;
    Ok(ComposedCredentialReaders {
        store: Arc::new(store),
        readback,
        dispatch,
        measurements,
        enrollment_store_authority,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn production_reader_composition_retains_the_paired_enrollment_half() {
        let source = include_str!("credential_reader.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        assert!(production.contains("CredentialEnrollmentAuthorityPair::new().split()"));
        assert!(production.contains("open_with_connection_and_authorities"));
        assert!(production.contains("measurements,"));
        assert!(production.contains("enrollment_store_authority,"));
    }
}
