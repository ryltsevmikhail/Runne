use super::readiness::{
    credential_access_policy, native_journal_keyring, native_withheld_tail_store,
};
use super::*;
use crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway;
use crate::application::workspace_internal::{
    ProtectedProviderDependencyCapsule, ProviderDependencyState,
};
use runne_observability::operational::RecoveryObservationRegistry;
mod credential_reader;

pub(super) const PROVIDER_POLICY_V1_TOKEN_BUDGET: u64 = 1_000_000;
pub(super) const PROVIDER_POLICY_V1_COST_BUDGET_MICROS: u64 = 10_000_000;
pub(super) const PROVIDER_POLICY_V1_EFFECT_TTL_SECONDS: u64 = 120;
pub(super) const PROVIDER_POLICY_V1_LEASE_SECONDS: u64 = 600;
pub(super) const PROVIDER_POLICY_V1_REVISION: u64 = 1;
pub struct DaemonCanonicalProviderService {
    pub(super) dispatch_store: Arc<SqliteProviderDispatchStore>,
    pub(super) execution_store: Arc<SqliteProviderExecutionStore>,
    pub(super) credential_store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) credential_readback: Option<Arc<dyn ProviderCredentialReadback>>,
    pub(super) runtime_store: Arc<runtime_store::DaemonProviderRuntimeStore>,
    pub(super) conversation_store: StoreTransaction,
    pub(super) conversation_service: Arc<dyn ConversationTextCommandService>,
    pub(super) adapter: Arc<dyn CanonicalProviderEffect>,
    pub(super) profile: Arc<SharedTextProviderProfile>,
    pub(super) provider_id: &'static str,
    pub(super) model_id: &'static str,
    pub(super) model_revision: &'static str,
    pub(super) keyring: Arc<dyn ProviderJournalKeyring>,
    pub(super) prohibited_content: Arc<dyn ProhibitedContentPort>,
    pub(super) scanner_store: Arc<SqliteProviderRecoveryStore>,
    pub(super) tail_store: Arc<dyn WithheldTailStore>,
    pub(super) runtime_authority_id: [u8; 16],
    pub(super) database_generation: u64,
    pub(super) runtime_generation: u64,
    pub(super) fencing_token: u64,
    pub(super) launch_capability: ProviderRuntimeLaunchCapability,
    pub(super) recovery_registry: Arc<RecoveryObservationRegistry>,
}

pub(crate) struct DaemonCanonicalProviderComposition {
    pub(crate) db_path: String,
    pub(crate) dispatch_connection: runne_store::schema::ManagedConnection,
    pub(crate) execution_connection: runne_store::schema::ManagedConnection,
    pub(crate) credential_connection: runne_store::schema::ManagedConnection,
    pub(crate) runtime_authority_id: [u8; 16],
    pub(crate) runtime_generation: u64,
    pub(crate) activation_provenance: DaemonActivationProvenance,
    pub(crate) expected_profile_digest: [u8; 32],
    pub(crate) conversation_store: StoreTransaction,
    pub(crate) conversation_service: Arc<dyn ConversationTextCommandService>,
    pub(crate) prohibited_content: Arc<dyn ProhibitedContentPort>,
    pub(crate) profile: Arc<SharedTextProviderProfile>,
    pub(crate) adapter_factory: Arc<ProviderEffectFactory>,
    pub(crate) provider_id: &'static str,
    pub(crate) model_id: &'static str,
    pub(crate) model_revision: &'static str,
    pub(crate) scope: &'static str,
    pub(crate) credential_id: ProviderCredentialId,
    pub(crate) dependencies: ProtectedProviderDependencyCapsule,
}

impl DaemonCanonicalProviderService {
    /// Performs every metadata-only pre-readiness gate and composes production adapters.
    pub(crate) async fn compose(
        composition: DaemonCanonicalProviderComposition,
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
            profile,
            adapter_factory,
            provider_id,
            model_id,
            model_revision,
            scope,
            credential_id,
            dependencies,
        } = composition;
        #[cfg(any(test, feature = "test-support"))]
        let (effect_source, retained_keyring, terminal_store_decorator, credential_versions) =
            match dependencies.into_provider_state() {
                ProviderDependencyState::Production => (None, None, None, None),
                ProviderDependencyState::LoopbackFixture {
                    effect,
                    keyring,
                    decorator,
                    credential_versions,
                } => (
                    Some(effect),
                    Some(keyring),
                    Some(decorator),
                    Some(credential_versions),
                ),
            };
        #[cfg(not(any(test, feature = "test-support")))]
        let (retained_keyring, terminal_store_decorator) = match dependencies.into_provider_state()
        {
            ProviderDependencyState::Production => (None, None),
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let effect_source: Option<Arc<dyn CanonicalProviderEffect>> = None;
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
            scope,
        )?;
        let recovery_registry = Arc::new(RecoveryObservationRegistry::new().0);
        let keyring =
            retained_keyring.unwrap_or_else(|| native_journal_keyring(runtime_authority_id));
        let tail_store: Arc<dyn WithheldTailStore> = if effect_source.is_some() {
            Arc::new(LoopbackWithheldTailStore::default())
        } else {
            native_withheld_tail_store(runtime_authority_id)
        };
        let runtime_store = runtime_store::compose_runtime_store(
            Arc::clone(&execution_store),
            runtime_generation,
            terminal_store_decorator,
        );
        #[cfg(any(test, feature = "test-support"))]
        let credentials = match effect_source.clone() {
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
            )?,
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let credentials = credential_reader::production(
            credential_connection,
            credential_id,
            adapter_factory.as_ref(),
        )?;
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
                execution
                    .create_and_activate_key(runtime_authority_id, 1, 1)
                    .map_err(|_| {
                        DaemonError::Bootstrap("provider journal key unavailable".into())
                    })?;
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
            credential_readback: credentials.readback,
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
            scanner_store,
            tail_store,
            runtime_authority_id,
            database_generation: 1,
            runtime_generation,
            fencing_token,
            launch_capability,
            recovery_registry,
        });
        match service.credential_readback.as_deref() {
            Some(reader) => {
                CredentialEnrollmentRecoveryGateway::new(service.credential_store.as_ref(), reader)
                    .reconcile_online(chrono::Utc::now().timestamp())
                    .map_err(|_| {
                        DaemonError::Bootstrap("credential enrollment recovery unavailable".into())
                    })?
            }
            None if effect_source.is_none() => {
                return Err(DaemonError::Bootstrap(
                    "provider credential reader unavailable".into(),
                ));
            }
            None => {}
        }
        service.recover_pending().await?;
        Ok(service)
    }
}

#[cfg(test)]
mod tests;
