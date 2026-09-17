use super::provider_startup::StartupProvider;
use super::workspace_internal::ProtectedProviderDependencyCapsule;
use super::*;
use crate::config::{Source, external_config_path, load_external_config};
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
use crate::protected_activation::VerifiedProtectedApplicationStart;

pub(crate) struct VerifiedOwnerPrivateConfig {
    config: ConfigurationSnapshot,
    bootstrap: BootstrapOutcome,
}

impl VerifiedOwnerPrivateConfig {
    fn load_fixed_source() -> Result<Self, DaemonError> {
        let config = load_external_config()?;
        if config.provider_activation.requires_openai_execution()
            || config.provider_activation.requires_deepseek_execution()
        {
            let source = config
                .provenance
                .get("provider_activation")
                .ok_or_else(|| {
                    DaemonError::Bootstrap(
                        "verified provider activation provenance is unavailable".into(),
                    )
                })?;
            if source.source != Source::SystemFile
                || source.path.as_deref() != external_config_path().to_str()
            {
                return Err(DaemonError::Bootstrap(
                    "verified provider activation provenance is unavailable".into(),
                ));
            }
        }
        DaemonApplication::validate_config(&config)?;
        let bootstrap = bootstrap(&config)?;
        Ok(Self { config, bootstrap })
    }

    pub(crate) const fn provider_activation(&self) -> &ProviderActivation {
        &self.config.provider_activation
    }

    pub(crate) const fn authority_id(&self) -> [u8; 16] {
        self.bootstrap.authority_id
    }

    pub(crate) fn config_digest(&self) -> &str {
        &self.config.digest
    }

    fn into_parts(self) -> (ConfigurationSnapshot, BootstrapOutcome) {
        (self.config, self.bootstrap)
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        config: ConfigurationSnapshot,
        bootstrap: BootstrapOutcome,
    ) -> Self {
        Self { config, bootstrap }
    }
}

/// Fully composed daemon with bootstrap locks, durable store, runtime,
/// canonical router, and shutdown authority kept alive together.
pub struct DaemonApplication {
    pub(super) bootstrap: BootstrapOutcome,
    pub(super) store: StoreTransaction,
    pub(super) http_host: LocalRuntimeTlsHost,
    pub(super) client_profile: Option<PublishedClientProfileV3>,
    pub(super) binding: RuntimeSessionBinding,
    pub(super) local_session_service: Arc<Mutex<LocalSessionService>>,
    pub(super) _bootstrap_reservation_store: Arc<SqliteBootstrapReservationStore>,
    pub(super) session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    pub(super) protected_activation: bool,
    pub(super) provider_activation: ProviderActivation,
    /// Metadata-only provider readiness, consumed only by the
    /// desktop-protected V2 readiness path; unread in featureless builds.
    #[allow(dead_code)]
    pub(super) provider_readiness: runne_api::ProviderActivationReadinessV1,
    pub(super) runtime_liveness: RuntimeHandle,
    pub(super) runtime_controller: RuntimeController,
    pub(super) _secret_broker: Arc<Mutex<SecretBroker>>,
    pub(super) task_supervisor: Arc<RuntimeTaskSupervisor>,
    pub(super) shutdown_timeout: Duration,
    #[cfg(feature = "desktop-protected")]
    pub(super) root_control: Option<Arc<crate::protected_activation::ProtectedRootControl>>,
    pub(super) runtime_capabilities: &'static [&'static str],
    pub(super) credential_enrollment_control: Option<
        Arc<super::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl>,
    >,
}

impl DaemonApplication {
    pub async fn start_external_from_fixed_source() -> Result<Self, DaemonError> {
        let verified = VerifiedOwnerPrivateConfig::load_fixed_source()?;
        Self::start_verified_external(verified, ProtectedProviderDependencyCapsule::production())
            .await
    }

    async fn start_verified_external(
        verified: VerifiedOwnerPrivateConfig,
        dependencies: ProtectedProviderDependencyCapsule,
    ) -> Result<Self, DaemonError> {
        let startup = StartupProvider::verified_external(&verified, dependencies);
        let (config, bootstrap) = verified.into_parts();
        Self::start_with_bootstrap(&config, bootstrap, startup).await
    }

    /// Bootstraps storage, starts the canonical runtime, builds the production
    /// router, and binds HTTP without accepting requests yet.
    pub async fn start(config: &ConfigurationSnapshot) -> Result<Self, DaemonError> {
        Self::validate_config(config)?;
        let startup = StartupProvider::deterministic(config)?;
        let bootstrap = bootstrap(config)?;
        Self::start_with_bootstrap(config, bootstrap, startup).await
    }

    /// Starts from an already authenticated protected bundled bootstrap.
    #[cfg(all(any(unix, windows), feature = "desktop-protected"))]
    pub(super) async fn start_protected(
        mut start: VerifiedProtectedApplicationStart,
        keys: ProtectedActivationKeys,
        dependencies: ProtectedProviderDependencyCapsule,
    ) -> Result<Self, DaemonError> {
        let enrollment_capability = start.take_enrollment_capability();
        let startup =
            StartupProvider::verified_protected(&start, keys, dependencies, enrollment_capability);
        let (config, bootstrap, _) = start.into_parts();
        Self::validate_config(&config)?;
        Self::start_with_bootstrap(&config, bootstrap, startup).await
    }

    fn validate_config(config: &ConfigurationSnapshot) -> Result<(), DaemonError> {
        if config.max_in_flight == 0 {
            return Err(DaemonError::Config(
                "max_in_flight must be greater than zero".to_owned(),
            ));
        }
        if config.shutdown_timeout_ms == 0 {
            return Err(DaemonError::Config(
                "shutdown_timeout_ms must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_startup_has_no_protected_provenance() {
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(
            directory.path(),
        ));

        assert!(
            !StartupProvider::deterministic(&config)
                .unwrap()
                .is_protected()
        );
    }
}
