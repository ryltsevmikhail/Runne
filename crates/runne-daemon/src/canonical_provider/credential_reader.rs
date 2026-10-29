use std::sync::Arc;

#[cfg(all(target_os = "macos", feature = "desktop-protected"))]
use runne_provider::CredentialAuthorityPair;
use runne_provider::{
    CredentialEnrollmentAuthorityPair, CredentialEnrollmentMeasurementAuthority,
    CredentialEnrollmentStoreAuthority,
};
#[cfg(not(all(target_os = "macos", feature = "desktop-protected")))]
use runne_secure_store::NativeProviderCredentialReaders;
use runne_secure_store::{
    ProviderCredentialAccessPolicy, ProviderCredentialDispatchMaterializer, ProviderCredentialId,
    ProviderCredentialReadback,
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
    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    pub(super) credential_service:
        Option<Arc<crate::protected_activation::CredentialServiceRuntimeGateway>>,
    pub(super) defer_initial_reconciliation: bool,
}

pub(super) fn compose(
    connection: ManagedConnection,
    _credential_id: ProviderCredentialId,
    _access: ProviderCredentialAccessPolicy,
    service_only: bool,
) -> Result<ComposedCredentialReaders, DaemonError> {
    let (enrollment_store_authority, measurements) =
        CredentialEnrollmentAuthorityPair::new().split();
    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    if service_only {
        let (lifecycle_authority, _) = CredentialAuthorityPair::new().split();
        let credential_service = Arc::new(
            crate::protected_activation::CredentialServiceRuntimeGateway::new(
                enrollment_store_authority.clone(),
                tokio::runtime::Handle::current(),
            )
            .with_legacy_readback(Arc::new(
                runne_secure_store::NativeLegacySourceReadback::new(_access.clone()),
            )),
        );
        let readback: Arc<dyn ProviderCredentialReadback> = credential_service.clone();
        let dispatch: Arc<dyn ProviderCredentialDispatchMaterializer> = credential_service.clone();
        let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
            connection,
            lifecycle_authority,
            enrollment_store_authority.clone(),
        )
        .map_err(|_| DaemonError::Bootstrap("provider credential lifecycle unavailable".into()))?;
        return Ok(ComposedCredentialReaders {
            store: Arc::new(store),
            readback,
            dispatch,
            measurements,
            enrollment_store_authority,
            credential_service: Some(credential_service),
            defer_initial_reconciliation: true,
        });
    }
    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    return Err(DaemonError::Bootstrap(
        "protected credential service registration is required".into(),
    ));
    #[cfg(not(all(target_os = "macos", feature = "desktop-protected")))]
    let _ = service_only;
    #[cfg(not(all(target_os = "macos", feature = "desktop-protected")))]
    let (lifecycle_authority, readback, dispatch, _) = {
        #[cfg(target_os = "linux")]
        if _credential_id == ProviderCredentialId::DeepSeek {
            let access = if service_only {
                Some(
                    crate::protected_activation::terminal_adoption::credential_access(&connection)?,
                )
            } else {
                crate::linux_cli_credential_host::execution_access_policy()?
            };
            if let Some(access) = access {
                let authority = runne_store::schema::read_authority_id(&connection)
                    .map_err(|_| {
                        DaemonError::Bootstrap("CLI credential authority unavailable".into())
                    })?
                    .ok_or_else(|| {
                        DaemonError::Bootstrap("CLI credential authority missing".into())
                    })?;
                NativeProviderCredentialReaders::new_cli_host(access, authority).into_parts()
            } else {
                NativeProviderCredentialReaders::new(_access.clone()).into_parts()
            }
        } else {
            NativeProviderCredentialReaders::new(_access.clone()).into_parts()
        }
        #[cfg(not(target_os = "linux"))]
        {
            NativeProviderCredentialReaders::new(_access.clone()).into_parts()
        }
    };
    #[cfg(not(all(target_os = "macos", feature = "desktop-protected")))]
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
        connection,
        lifecycle_authority,
        enrollment_store_authority.clone(),
    )
    .map_err(|_| DaemonError::Bootstrap("provider credential lifecycle unavailable".into()))?;
    #[cfg(all(
        feature = "test-support",
        not(all(target_os = "macos", feature = "desktop-protected"))
    ))]
    prove_existing_local_material(&store, _credential_id, &_access)?;
    #[cfg(not(all(target_os = "macos", feature = "desktop-protected")))]
    Ok(ComposedCredentialReaders {
        store: Arc::new(store),
        readback,
        dispatch,
        measurements,
        enrollment_store_authority,
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        credential_service: None,
        defer_initial_reconciliation: false,
    })
}

#[cfg(all(
    feature = "test-support",
    not(all(target_os = "macos", feature = "desktop-protected"))
))]
fn prove_existing_local_material(
    store: &SqliteProviderCredentialLifecycleStore,
    credential_id: ProviderCredentialId,
    access: &ProviderCredentialAccessPolicy,
) -> Result<(), DaemonError> {
    use runne_provider::{ProviderCredentialEnrollmentStore as _, ProviderId};

    if !runne_api::test_support::local_native_enrollment_enabled() {
        return Ok(());
    }
    let provider = ProviderId::new(credential_id.account())
        .map_err(|_| DaemonError::Bootstrap("credential reader probe unavailable".into()))?;
    let lifecycle = match store.lifecycle_snapshot(&provider) {
        Ok(value) => value,
        Err(runne_provider::CredentialLifecycleError::NotFound) => return Ok(()),
        Err(_) => {
            return Err(DaemonError::Bootstrap(
                "credential reader probe unavailable".into(),
            ));
        }
    };
    if let Some(reference) = lifecycle.active_version() {
        runne_secure_store::test_support::prove_current_reader_can_load_exact(reference, access)
            .map_err(|_| DaemonError::Bootstrap("credential reader probe unavailable".into()))?;
    }
    Ok(())
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
