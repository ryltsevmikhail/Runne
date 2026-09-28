use super::readiness::{
    credential_access_policy, native_journal_keyring, native_withheld_tail_store,
};
use super::*;
#[cfg(test)]
use crate::application::workspace_internal::ProtectedProviderDependencyCapsule;
#[cfg(test)]
use runne_secure_store::ProviderCredentialId;
mod credential_reader;
mod credential_reconciliation;
mod dependencies;
mod enrollment_control;
#[cfg(all(feature = "test-support", not(test)))]
mod fixture_credentials;
mod input;
mod policy;
pub(crate) use input::DaemonCanonicalProviderComposition;
pub(super) use policy::*;
pub struct DaemonCanonicalProviderService {
    pub(super) dispatch_store: Arc<SqliteProviderDispatchStore>,
    pub(super) execution_store: Arc<SqliteProviderExecutionStore>,
    pub(super) credential_store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) quota_store: Arc<runne_provider_quota::QuotaStateStore>,
    #[allow(dead_code, reason = "used by protected macOS verification")]
    pub(super) enrollment_store_authority:
        Option<runne_provider::CredentialEnrollmentStoreAuthority>,
    pub(super) credential_readback: Option<Arc<dyn ProviderCredentialReadback>>,
    pub(super) credential_enrollment_control:
        Option<Arc<crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl>>,
    pub(super) runtime_store: Arc<runtime_store::DaemonProviderRuntimeStore>,
    pub(super) conversation_store: StoreTransaction,
    pub(super) conversation_service: Arc<dyn ConversationTextCommandService>,
    pub(super) adapter: Arc<dyn CanonicalProviderEffect>,
    pub(super) profile: Arc<SharedTextProviderProfile>,
    pub(super) provider_id: std::borrow::Cow<'static, str>,
    pub(super) model_id: std::borrow::Cow<'static, str>,
    pub(super) model_revision: std::borrow::Cow<'static, str>,
    pub(super) keyring: Arc<dyn ProviderJournalKeyring>,
    pub(super) prohibited_content: Arc<dyn ProhibitedContentPort>,
    pub(super) trust: Option<crate::application::trust_delivery::DeliveryTrustGate>,
    pub(super) scanner_store: Arc<SqliteProviderRecoveryStore>,
    pub(super) tail_store: Arc<dyn WithheldTailStore>,
    pub(super) runtime_authority_id: [u8; 16],
    pub(super) database_generation: u64,
    pub(super) runtime_generation: u64,
    pub(super) fencing_token: u64,
    pub(super) launch_capability: ProviderRuntimeLaunchCapability,
    pub(super) renewal_dispatch_gate: super::dispatch_gate::ProviderDispatchGate,
    pub(super) recovery_registry: Arc<runne_observability::operational::RecoveryObservationRegistry>,
}
impl DaemonCanonicalProviderService {
    /// The provider model pinned by this composition; exact-model admission
    /// compares requested models against it (D1.4b, 2026-09-28).
    pub fn pinned_model_id(&self) -> &str {
        &self.model_id
    }

    pub(crate) async fn compose(
        c: DaemonCanonicalProviderComposition,
    ) -> Result<Arc<Self>, DaemonError> {
        let DaemonCanonicalProviderComposition {
            db_path,
            dispatch_connection,
            execution_connection,
            credential_connection,
            runtime_authority_id,
            runtime_generation,
            activation_provenance,
            expected_profile_digest,
            conversation_store,
            conversation_service,
            prohibited_content,
            trust,
            profile,
            adapter_factory,
            provider_id,
            model_id,
            model_revision,
            scope,
            credential_id,
            quota_store,
            dependencies,
        } = c;
        let selected_dependencies = dependencies::select(dependencies);
        let effect_source = selected_dependencies.effect;
        #[cfg(all(feature = "test-support", not(test)))]
        let adapter_override = selected_dependencies.adapter_override;
        let retained_keyring = selected_dependencies.keyring;
        let terminal_store_decorator = selected_dependencies.decorator;
        let fixture_transport = selected_dependencies.fixture_transport;
        #[cfg(test)]
        let credential_versions = selected_dependencies.credential_versions;
        if profile.profile_digest() != expected_profile_digest {
            return Err(DaemonError::Bootstrap(
                "provider profile binding mismatch".into(),
            ));
        }
        let dispatch_store = Arc::new(
            SqliteProviderDispatchStore::open_with_connection(&db_path, dispatch_connection)
                .map_err(|_| {
                    DaemonError::Bootstrap("provider dispatch store unavailable".into())
                })?,
        );
        let execution_store = Arc::new(
            SqliteProviderExecutionStore::open_with_connection(&db_path, execution_connection)
                .map_err(|_| {
                    DaemonError::Bootstrap("provider execution store unavailable".into())
                })?,
        );
        let scanner_store = Arc::new(
            SqliteProviderRecoveryStore::open(std::path::Path::new(&db_path), runtime_authority_id)
                .map_err(|_| {
                    DaemonError::Bootstrap("provider scanner recovery unavailable".into())
                })?,
        );
        let fencing_token = runtime_generation;
        let launch_capability = runtime_launch::activate(
            execution_store.as_ref(),
            runtime_authority_id,
            runtime_generation,
            &activation_provenance,
            profile.as_ref(),
            &scope,
        )?;
        let registry =
            Arc::new(runne_observability::operational::RecoveryObservationRegistry::new().0);
        let keyring =
            retained_keyring.unwrap_or_else(|| native_journal_keyring(runtime_authority_id));
        let tail_store: Arc<dyn WithheldTailStore> = if fixture_transport {
            Arc::new(LoopbackWithheldTailStore::default())
        } else {
            native_withheld_tail_store(runtime_authority_id)
        };
        let runtime_store = runtime_store::compose_runtime_store(
            Arc::clone(&execution_store),
            runtime_generation,
            terminal_store_decorator,
        );
        #[cfg(test)]
        let mut credentials = match effect_source.clone() {
            Some(effect) => credential_reader::fixture(
                credential_connection,
                runtime_authority_id,
                runtime_generation,
                credential_id,
                credential_versions,
                effect,
            )?,
            None => credential_reader::production(
                credential_connection,
                credential_id,
                adapter_factory.as_ref(),
                activation_provenance.is_protected(),
            )?,
        };
        #[cfg(all(feature = "test-support", not(test)))]
        let mut credentials = match effect_source.clone() {
            Some(effect) => credential_reader::fixture(
                credential_connection,
                runtime_authority_id,
                runtime_generation,
                credential_id,
                effect,
            )?,
            None => {
                let selected = adapter_override
                    .as_deref()
                    .unwrap_or(adapter_factory.as_ref());
                credential_reader::production(
                    credential_connection,
                    credential_id,
                    selected,
                    activation_provenance.is_protected(),
                )?
            }
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let mut credentials = credential_reader::production(
            credential_connection,
            credential_id,
            adapter_factory.as_ref(),
            activation_provenance.is_protected(),
        )?;
        let defer_initial_credential_reconciliation = credentials.defer_initial_reconciliation;
        let enrollment_store_authority = credentials
            .enrollment_authorities
            .as_ref()
            .map(|a| a.store.clone());
        let credential_enrollment_control =
            enrollment_control::compose(&mut credentials, runtime_authority_id, 1)?;
        let matcher = ProhibitedContentCredentialMatcher::new(prohibited_content.as_ref());
        let redaction = ProviderEventRedactionBoundary::new(
            tail_store.as_ref(),
            scanner_store.as_ref(),
            &matcher,
        );
        let execution = RuntimeProviderExecution::new(
            keyring.as_ref(),
            runtime_store.as_ref(),
            profile.as_ref(),
            prohibited_content.as_ref(),
            &redaction,
        );
        match execution_store
            .active_journal_key_binding()
            .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?
        {
            Some(_) => {
                execution
                    .preflight_existing_active_key(runtime_authority_id, 1)
                    .map_err(|_| {
                        DaemonError::Bootstrap("provider journal key unavailable".into())
                    })?;
            }
            None => {
                RuntimeProviderExecution::<
                    dyn ProviderJournalKeyring,
                    runtime_store::DaemonProviderRuntimeStore,
                    SharedTextProviderProfile,
                >::create_and_activate_key(&execution, runtime_authority_id, 1, 1)
                .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?;
            }
        }
        let journal_binding = execution
            .preflight_existing_active_key(runtime_authority_id, 1)
            .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?;
        execution_store
            .install_online_effect_proof_capability(keyring.as_ref(), journal_binding)
            .map_err(|_| {
                DaemonError::Bootstrap("provider online effect proof unavailable".into())
            })?;
        let journal_status = keyring
            .provider_journal_key_status(
                runne_secure_store::ProviderJournalKeyRef::new(
                    journal_binding.key_id(),
                    journal_binding.key_version(),
                    journal_binding.runtime_authority_id(),
                    journal_binding.database_generation(),
                )
                .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?,
            )
            .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?;
        ProviderReadinessEvidence {
            profile_id: profile.profile_id().to_owned(),
            profile_digest: profile.profile_digest(),
            activation_profile_id: profile.profile_id().to_owned(),
            activation_profile_digest: expected_profile_digest,
            retained_key_backend: keyring.retains_multiple_provider_journal_keys(),
            credential_status: credentials.status,
            journal_binding: Some(journal_binding),
            journal_key_status: journal_status,
            runtime_authority_id,
            database_generation: 1,
        }
        .validate_control_plane()
        .map_err(|error| DaemonError::Bootstrap(error.to_string()))?;
        let service = Arc::new(Self {
            dispatch_store,
            execution_store,
            credential_store: credentials.store,
            enrollment_store_authority,
            quota_store,
            credential_readback: credentials.readback,
            credential_enrollment_control,
            runtime_store,
            conversation_store,
            conversation_service,
            adapter: credentials.adapter,
            profile,
            provider_id,
            model_id,
            model_revision,
            keyring,
            prohibited_content,
            trust,
            scanner_store,
            tail_store,
            runtime_authority_id,
            database_generation: 1,
            runtime_generation,
            fencing_token,
            launch_capability,
            renewal_dispatch_gate: super::dispatch_gate::ProviderDispatchGate::default(),
            recovery_registry: registry,
        });
        #[cfg(any(
            all(test, unix),
            all(
                feature = "desktop-protected",
                target_os = "macos",
                target_arch = "aarch64"
            )
        ))]
        service.install_remote_verification()?;
        credential_reconciliation::reconcile_initial(
            service.as_ref(),
            defer_initial_credential_reconciliation,
            effect_source.is_some(),
        )?;
        service.recover_pending().await?;
        Ok(service)
    }
}
#[cfg(test)]
mod tests;
