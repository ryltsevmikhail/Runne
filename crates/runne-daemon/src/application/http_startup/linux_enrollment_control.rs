use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use crate::canonical_provider::readiness::native_credential_access_policy;
use crate::error::DaemonError;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_provider::CredentialEnrollmentAuthorityPair;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_secure_store::NativeProviderCredentialReaders;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_store::provider::SqliteProviderCredentialLifecycleStore;

pub(super) fn runtime_config(max_in_flight: u32) -> Result<super::RuntimeConfig, DaemonError> {
    Ok(super::RuntimeConfig {
        max_in_flight_requests: usize::try_from(max_in_flight).map_err(|_| {
            DaemonError::Config("max_in_flight does not fit this platform".to_owned())
        })?,
        ..super::RuntimeConfig::default()
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compose_startup_enrollment(
    config: &super::ConfigurationSnapshot,
    runtime_authority: [u8; 16],
    replay_lineage: runne_domain::id::EventLogLineageId,
    provider_service: Option<&Arc<crate::canonical_provider::DaemonCanonicalProviderService>>,
    protected: bool,
    installed_candidate: bool,
    root_admission_keys: Option<&runne_api::ProtectedActivationKeys>,
    capability: Option<&crate::protected_activation::VerifiedProtectedEnrollmentCapability>,
) -> Result<super::enrollment::EnrollmentHttpComposition, DaemonError> {
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    let candidate = protected && installed_candidate;
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    let control = control_or_compose(
        candidate,
        provider_service.and_then(|service| service.credential_enrollment_control()),
        || {
            let connection = super::super::open_runtime_connection(
                &config.db_path,
                runne_store::schema::ConnectionMode::ValidatedReopen,
                runtime_authority,
                replay_lineage,
                "protected enrollment credential store",
            )?;
            compose(connection, runtime_authority)
        },
    )?;
    #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
    let _ = (
        config,
        runtime_authority,
        replay_lineage,
        installed_candidate,
    );
    #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
    let control = provider_service.and_then(|service| service.credential_enrollment_control());
    super::enrollment::compose(
        provider_service,
        control,
        protected,
        root_admission_keys,
        capability,
    )
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
fn control_or_compose<T>(
    protected: bool,
    existing: Option<T>,
    compose: impl FnOnce() -> Result<T, DaemonError>,
) -> Result<Option<T>, DaemonError> {
    match existing {
        Some(control) => Ok(Some(control)),
        None if protected => compose().map(Some),
        None => Ok(None),
    }
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
pub(super) fn compose(
    connection: runne_store::schema::ManagedConnection,
    runtime_authority: [u8; 16],
) -> Result<Arc<DaemonProviderCredentialEnrollmentControl>, DaemonError> {
    let access = native_credential_access_policy()?;
    let (lifecycle_authority, readback, _dispatch, _) =
        NativeProviderCredentialReaders::new(access).into_parts();
    let (enrollment_store_authority, measurements) =
        CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
        connection,
        lifecycle_authority,
        enrollment_store_authority.clone(),
    )
    .map_err(|_| DaemonError::Bootstrap("provider credential lifecycle unavailable".into()))?;
    DaemonProviderCredentialEnrollmentControl::new(
        Arc::new(store),
        readback,
        measurements,
        enrollment_store_authority,
        runtime_authority,
        1,
    )
    .map(Arc::new)
    .map_err(|_| DaemonError::Bootstrap("provider credential control unavailable".into()))
}

#[cfg(test)]
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[path = "linux_enrollment_control/tests.rs"]
mod tests;
