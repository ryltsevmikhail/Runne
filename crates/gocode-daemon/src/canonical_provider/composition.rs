use super::projection::{derived_identity, policy_binding_digest};
use super::readiness::{
    credential_access_policy, native_journal_keyring, native_withheld_tail_store,
};
use super::*;
use crate::application::workspace_internal::{
    ProtectedProviderDependencyCapsule, ProviderDependencyState,
};
use gocode_observability::operational::RecoveryObservationRegistry;
/// Normative cumulative provider token budget for development/ad-hoc policy V1.
pub(super) const PROVIDER_POLICY_V1_TOKEN_BUDGET: u64 = 1_000_000;
/// Normative cumulative provider cost budget in micro-USD.
pub(super) const PROVIDER_POLICY_V1_COST_BUDGET_MICROS: u64 = 10_000_000;
/// Normative single-effect authority lifetime.
pub(super) const PROVIDER_POLICY_V1_EFFECT_TTL_SECONDS: u64 = 120;
/// Normative capability and approval lease.
pub(super) const PROVIDER_POLICY_V1_LEASE_SECONDS: u64 = 600;
/// Normative policy revision and revocation epoch.
pub(super) const PROVIDER_POLICY_V1_REVISION: u64 = 1;
/// Runs concrete OpenAI composition only for the exact selected activation.
/// Deterministic mode returns without evaluating the probe future.
pub async fn compose_selected_provider<T, F, Fut>(
    activation: &ProviderActivation,
    compose: F,
) -> Result<Option<T>, DaemonError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, DaemonError>>,
{
    if activation.requires_openai_execution() {
        compose().await.map(Some)
    } else {
        Ok(None)
    }
}
/// Fully composed canonical OpenAI service. Concrete adapters remain here.
pub struct DaemonCanonicalOpenAiService {
    pub(super) dispatch_store: Arc<SqliteProviderDispatchStore>,
    pub(super) execution_store: Arc<SqliteProviderExecutionStore>,
    pub(super) credential_store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) runtime_store: Arc<runtime_store::DaemonProviderRuntimeStore>,
    pub(super) conversation_store: StoreTransaction,
    pub(super) conversation_service: Arc<dyn ConversationTextCommandService>,
    pub(super) adapter: Arc<dyn gocode_daemon_openai_effect::OpenAiEffect>,
    pub(super) profile: Arc<OpenAiResponsesTextProfile>,
    pub(super) keyring: Arc<dyn ProviderJournalKeyring>,
    pub(super) prohibited_content: Arc<dyn ProhibitedContentPort>,
    pub(super) scanner_store: Arc<SqliteProviderRecoveryStore>,
    pub(super) tail_store: Arc<dyn WithheldTailStore>,
    pub(super) runtime_authority_id: [u8; 16],
    pub(super) database_generation: u64,
    pub(super) runtime_generation: u64,
    pub(super) fencing_token: u64,
    pub(super) recovery_registry: Arc<RecoveryObservationRegistry>,
}

pub(crate) struct DaemonCanonicalOpenAiComposition {
    pub(crate) db_path: String,
    pub(crate) dispatch_connection: gocode_store::schema::ManagedConnection,
    pub(crate) execution_connection: gocode_store::schema::ManagedConnection,
    pub(crate) credential_connection: gocode_store::schema::ManagedConnection,
    pub(crate) runtime_authority_id: [u8; 16],
    pub(crate) runtime_generation: u64,
    pub(crate) activation_provenance: DaemonActivationProvenance,
    pub(crate) expected_profile_digest: [u8; 32],
    pub(crate) conversation_store: StoreTransaction,
    pub(crate) conversation_service: Arc<dyn ConversationTextCommandService>,
    pub(crate) prohibited_content: Arc<dyn ProhibitedContentPort>,
    pub(crate) dependencies: ProtectedProviderDependencyCapsule,
}

impl DaemonCanonicalOpenAiService {
    /// Performs every metadata-only pre-readiness gate and composes production adapters.
    pub(crate) async fn compose(
        composition: DaemonCanonicalOpenAiComposition,
    ) -> Result<Arc<Self>, DaemonError> {
        let DaemonCanonicalOpenAiComposition {
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
            dependencies,
        } = composition;
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
        let profile = Arc::new(
            OpenAiResponsesTextProfile::from_json(include_bytes!(
                "../../../../docs/profiles/openai-responses-text-v1.json"
            ))
            .map_err(|_| DaemonError::Bootstrap("provider profile unavailable".into()))?,
        );
        if profile.profile_digest() != expected_profile_digest {
            return Err(DaemonError::Bootstrap(
                "provider profile binding mismatch".into(),
            ));
        }
        let status = if effect_source.is_some() {
            ProviderCredentialStatus::Configured
        } else {
            let access = credential_access_policy()?;
            let credential_store: Arc<dyn ProviderCredentialStore> =
                Arc::new(NativeProviderCredentialStore::new());
            crate::canonical_provider_factory::provider_credential_status(credential_store, access)
                .await?
        };
        if status != ProviderCredentialStatus::Configured {
            return Err(DaemonError::Bootstrap(
                "provider credential unavailable".into(),
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
        let policy_binding =
            policy_binding_digest(activation_provenance.digest(), profile.as_ref());
        execution_store
            .install_runtime_authority_and_advance_worker_lease(&ProviderRuntimeAuthorityConfig {
                runtime_authority_id,
                database_generation: 1,
                principal_id: "local-owner".to_owned(),
                owner_id: derived_identity("owner", policy_binding),
                scope: "provider.openai.responses.text".to_owned(),
                generation: runtime_generation,
                fencing_token,
                capability_grant_id: derived_identity("capability", policy_binding),
                capability_revision: PROVIDER_POLICY_V1_REVISION,
                capability_allowed: true,
                capability_revocation_epoch: PROVIDER_POLICY_V1_REVISION,
                approval_id: derived_identity("approval", policy_binding),
                approval_revision: PROVIDER_POLICY_V1_REVISION,
                approval_allowed: true,
                approval_revocation_epoch: PROVIDER_POLICY_V1_REVISION,
                profile_digest: profile.profile_digest(),
                pricing_revision_digest: profile.pricing_revision_digest(),
                activation_binding_kind: activation_provenance.kind(),
                activation_binding_digest: activation_provenance.digest(),
                token_budget_limit: PROVIDER_POLICY_V1_TOKEN_BUDGET,
                cost_budget_limit_micros: PROVIDER_POLICY_V1_COST_BUDGET_MICROS,
                authority_ttl_seconds: PROVIDER_POLICY_V1_EFFECT_TTL_SECONDS,
                lease_ttl_seconds: PROVIDER_POLICY_V1_LEASE_SECONDS,
            })
            .map_err(|_| DaemonError::Bootstrap("provider authority unavailable".into()))?;
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
        let credentials = super::credential_versions::compose_credential_lifecycle(
            credential_connection,
            runtime_authority_id,
            runtime_generation,
            effect_source.is_some(),
            credential_versions,
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
        let journal_status = keyring
            .provider_journal_key_status(
                gocode_secure_store::ProviderJournalKeyRef::new(
                    journal_binding.key_id(),
                    journal_binding.key_version(),
                    journal_binding.runtime_authority_id(),
                    journal_binding.database_generation(),
                )
                .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?,
            )
            .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?;
        OpenAiReadinessEvidence {
            profile_id: profile.profile_id().to_owned(),
            profile_digest: profile.profile_digest(),
            activation_profile_id: gocode_provider_openai::OPENAI_RESPONSES_PROFILE_ID.to_owned(),
            activation_profile_digest: expected_profile_digest,
            retained_key_backend: keyring.retains_multiple_provider_journal_keys(),
            credential_status: status,
            journal_binding: Some(journal_binding),
            journal_key_status: journal_status,
            runtime_authority_id,
            database_generation: 1,
        }
        .validate()
        .map_err(|error| DaemonError::Bootstrap(error.to_string()))?;
        let adapter = match effect_source {
            Some(effect) => effect,
            None => <dyn gocode_daemon_openai_effect::OpenAiEffect>::production(
                credentials.native_authority,
            )
            .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))?,
        };
        let service = Arc::new(Self {
            dispatch_store,
            execution_store,
            credential_store: credentials.store,
            runtime_store,
            conversation_store,
            conversation_service,
            adapter,
            profile,
            keyring,
            prohibited_content,
            scanner_store,
            tail_store,
            runtime_authority_id,
            database_generation: 1,
            runtime_generation,
            fencing_token,
            recovery_registry,
        });
        service.recover_pending().await?;
        Ok(service)
    }
}

#[cfg(test)]
mod tests;
