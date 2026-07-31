//! Concrete OpenAI canonical execution composition owned by the daemon root.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_application::conversation_text_service::ConversationTextCommandService;
use gocode_application::ports::ConversationRepository;
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::provider::{
    ProviderCoordinatorOutcome, ProviderCoordinatorRequest, ProviderDispatchCoordinator,
    ProviderExecutionStore, ProviderJournalKeyBinding,
};
use gocode_domain::conversation::ConversationEvent;
use gocode_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderPort, ProviderStreamEventKind, ProviderTerminalDisposition, ProviderTextInput,
    ProviderUsage, StreamCursor,
};
use gocode_provider_openai::{
    OPENAI_MODEL_ID, OPENAI_MODEL_REVISION, OpenAiCredentialError, OpenAiCredentialMaterializer,
    OpenAiHttpTransport, OpenAiProviderAdapter, OpenAiResponsesTextProfile, OpenAiTransportPolicy,
};
use gocode_runtime::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
    CanonicalProviderExecutionService,
};
use gocode_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderEventJournalContext, RuntimeProviderExecution,
    RuntimeProviderExecutionError,
};
use gocode_secure_store::{
    NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialStatus, ProviderCredentialStore, ProviderJournalKeyStatus,
    ProviderJournalKeyring, SecureStoreError,
};
use gocode_store::provider::{
    ProviderRuntimeAuthorityConfig, SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
use gocode_store::store::StoreTransaction;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::DaemonError;
use crate::provider_activation::ProviderActivation;

/// Normative cumulative provider token budget for development/ad-hoc policy V1.
pub const PROVIDER_POLICY_V1_TOKEN_BUDGET: u64 = 1_000_000;
/// Normative cumulative provider cost budget in micro-USD.
pub const PROVIDER_POLICY_V1_COST_BUDGET_MICROS: u64 = 10_000_000;
/// Normative single-effect authority lifetime.
pub const PROVIDER_POLICY_V1_EFFECT_TTL_SECONDS: u64 = 120;
/// Normative capability and approval lease.
pub const PROVIDER_POLICY_V1_LEASE_SECONDS: u64 = 600;
/// Normative policy revision and revocation epoch.
pub const PROVIDER_POLICY_V1_REVISION: u64 = 1;

/// Typed pre-readiness failures for exact OpenAI composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenAiReadinessError {
    /// Exact profile artifact or activation binding differs.
    #[error("provider profile binding mismatch")]
    ProfileBinding,
    /// Native backend cannot support credential and retained journal keys.
    #[error("provider secure-store backend unsupported")]
    SecureStoreBackend,
    /// Credential metadata is not exactly configured.
    #[error("provider credential unavailable")]
    Credential,
    /// Active database-bound journal key metadata is absent or mismatched.
    #[error("provider journal key unavailable")]
    JournalKey,
}

/// Non-secret evidence required before OpenAI readiness can be emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiReadinessEvidence {
    /// Parsed exact profile identity.
    pub profile_id: String,
    /// Parsed exact profile digest.
    pub profile_digest: [u8; 32],
    /// Activation-bound profile identity.
    pub activation_profile_id: String,
    /// Activation-bound profile digest.
    pub activation_profile_digest: [u8; 32],
    /// Whether native retained-key support exists.
    pub retained_key_backend: bool,
    /// Credential metadata status only.
    pub credential_status: ProviderCredentialStatus,
    /// Active database key binding, without bytes.
    pub journal_binding: Option<ProviderJournalKeyBinding>,
    /// Native metadata-only key status.
    pub journal_key_status: ProviderJournalKeyStatus,
    /// Expected stable runtime authority.
    pub runtime_authority_id: [u8; 16],
    /// Expected database generation.
    pub database_generation: u64,
}

impl OpenAiReadinessEvidence {
    /// Validates every exact non-secret gate.
    pub fn validate(&self) -> Result<(), OpenAiReadinessError> {
        if self.profile_id != gocode_provider_openai::OPENAI_RESPONSES_PROFILE_ID
            || self.profile_id != self.activation_profile_id
            || self.profile_digest != self.activation_profile_digest
        {
            return Err(OpenAiReadinessError::ProfileBinding);
        }
        if !self.retained_key_backend {
            return Err(OpenAiReadinessError::SecureStoreBackend);
        }
        if self.credential_status != ProviderCredentialStatus::Configured {
            return Err(OpenAiReadinessError::Credential);
        }
        let binding = self
            .journal_binding
            .ok_or(OpenAiReadinessError::JournalKey)?;
        if self.journal_key_status != ProviderJournalKeyStatus::Available
            || binding.runtime_authority_id() != self.runtime_authority_id
            || binding.database_generation() != self.database_generation
        {
            return Err(OpenAiReadinessError::JournalKey);
        }
        Ok(())
    }
}

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

struct NativeOpenAiCredentialMaterializer {
    store: Arc<dyn ProviderCredentialStore>,
    access: ProviderCredentialAccessPolicy,
}

impl OpenAiCredentialMaterializer for NativeOpenAiCredentialMaterializer {
    fn materialize(
        &self,
    ) -> gocode_provider::ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, OpenAiCredentialError>>
    {
        let store = Arc::clone(&self.store);
        let access = self.access.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store
                    .load_provider_credential(ProviderCredentialId::OpenAi, &access)
                    .map(|material| material.with_bytes(|bytes| Zeroizing::new(bytes.to_vec())))
                    .map_err(map_credential_error)
            })
            .await
            .map_err(|_| OpenAiCredentialError::AccessDenied)?
        })
    }
}

/// Fully composed canonical OpenAI service. Concrete adapters remain here.
pub struct DaemonCanonicalOpenAiService {
    dispatch_store: Arc<SqliteProviderDispatchStore>,
    execution_store: Arc<SqliteProviderExecutionStore>,
    conversation_store: StoreTransaction,
    conversation_service: Arc<dyn ConversationTextCommandService>,
    adapter: Arc<dyn ProviderPort>,
    profile: Arc<OpenAiResponsesTextProfile>,
    keyring: Arc<dyn ProviderJournalKeyring>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
}

pub(crate) struct DaemonCanonicalOpenAiComposition {
    pub(crate) db_path: String,
    pub(crate) runtime_authority_id: [u8; 16],
    pub(crate) runtime_generation: u64,
    pub(crate) activation_identity: [u8; 32],
    pub(crate) expected_profile_digest: [u8; 32],
    pub(crate) conversation_store: StoreTransaction,
    pub(crate) conversation_service: Arc<dyn ConversationTextCommandService>,
    pub(crate) prohibited_content: Arc<dyn ProhibitedContentPort>,
}

impl DaemonCanonicalOpenAiService {
    /// Performs every metadata-only pre-readiness gate and composes production adapters.
    pub(crate) async fn compose(
        composition: DaemonCanonicalOpenAiComposition,
    ) -> Result<Arc<Self>, DaemonError> {
        let DaemonCanonicalOpenAiComposition {
            db_path,
            runtime_authority_id,
            runtime_generation,
            activation_identity,
            expected_profile_digest,
            conversation_store,
            conversation_service,
            prohibited_content,
        } = composition;
        let profile = Arc::new(
            OpenAiResponsesTextProfile::from_json(include_bytes!(
                "../../../docs/profiles/openai-responses-text-v1.json"
            ))
            .map_err(|_| DaemonError::Bootstrap("provider profile unavailable".into()))?,
        );
        if profile.profile_digest() != expected_profile_digest {
            return Err(DaemonError::Bootstrap(
                "provider profile binding mismatch".into(),
            ));
        }
        let access = credential_access_policy()?;
        let credential_store: Arc<dyn ProviderCredentialStore> =
            Arc::new(NativeProviderCredentialStore::new());
        let status_store = Arc::clone(&credential_store);
        let status_access = access.clone();
        let status = tokio::task::spawn_blocking(move || {
            status_store.provider_credential_status(ProviderCredentialId::OpenAi, &status_access)
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider credential status unavailable".into()))?
        .map_err(|_| DaemonError::Bootstrap("provider credential status unavailable".into()))?;
        if status != ProviderCredentialStatus::Configured {
            return Err(DaemonError::Bootstrap(
                "provider credential unavailable".into(),
            ));
        }
        let dispatch_store = Arc::new(
            SqliteProviderDispatchStore::open(std::path::Path::new(&db_path)).map_err(|_| {
                DaemonError::Bootstrap("provider dispatch store unavailable".into())
            })?,
        );
        let execution_store = Arc::new(
            SqliteProviderExecutionStore::open(std::path::Path::new(&db_path)).map_err(|_| {
                DaemonError::Bootstrap("provider execution store unavailable".into())
            })?,
        );
        let now = unix_seconds()?;
        let expires_at = now
            .checked_add(PROVIDER_POLICY_V1_LEASE_SECONDS)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| DaemonError::Bootstrap("provider policy clock unavailable".into()))?;
        let fencing_token = runtime_generation;
        let policy_binding = policy_binding_digest(activation_identity, profile.as_ref());
        execution_store
            .install_runtime_authority(&ProviderRuntimeAuthorityConfig {
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
                approval_id: derived_identity("approval", policy_binding),
                approval_revision: PROVIDER_POLICY_V1_REVISION,
                approval_allowed: true,
                approval_expires_at: expires_at,
                profile_digest: profile.profile_digest(),
                pricing_revision_digest: profile.pricing_revision_digest(),
                token_budget_limit: PROVIDER_POLICY_V1_TOKEN_BUDGET,
                cost_budget_limit_micros: PROVIDER_POLICY_V1_COST_BUDGET_MICROS,
                authority_ttl_seconds: PROVIDER_POLICY_V1_EFFECT_TTL_SECONDS,
            })
            .map_err(|_| DaemonError::Bootstrap("provider authority unavailable".into()))?;
        execution_store
            .advance_worker_lease(runtime_generation, fencing_token)
            .map_err(|_| DaemonError::Bootstrap("provider generation unavailable".into()))?;
        let keyring = native_journal_keyring(runtime_authority_id);
        let execution = RuntimeProviderExecution::new(
            keyring.as_ref(),
            execution_store.as_ref(),
            profile.as_ref(),
            prohibited_content.as_ref(),
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
        let policy = OpenAiTransportPolicy::for_profile(profile.as_ref())
            .map_err(|_| DaemonError::Bootstrap("provider transport policy unavailable".into()))?;
        let transport = OpenAiHttpTransport::new(policy)
            .map_err(|_| DaemonError::Bootstrap("provider transport unavailable".into()))?;
        let adapter: Arc<dyn ProviderPort> = Arc::new(
            OpenAiProviderAdapter::new(
                profile.as_ref().clone(),
                transport,
                NativeOpenAiCredentialMaterializer {
                    store: credential_store,
                    access,
                },
            )
            .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))?,
        );
        let service = Arc::new(Self {
            dispatch_store,
            execution_store,
            conversation_store,
            conversation_service,
            adapter,
            profile,
            keyring,
            prohibited_content,
            runtime_authority_id,
            database_generation: 1,
        });
        service.recover_pending().await?;
        Ok(service)
    }

    async fn recover_pending(&self) -> Result<(), DaemonError> {
        let execution_store = Arc::clone(&self.execution_store);
        let profile = Arc::clone(&self.profile);
        let keyring = Arc::clone(&self.keyring);
        let prohibited = Arc::clone(&self.prohibited_content);
        let application = ConversationProviderTerminalApplication::new(
            self.conversation_store.clone(),
            Arc::clone(&self.conversation_service),
        );
        let authority = self.runtime_authority_id;
        let generation = self.database_generation;
        tokio::task::spawn_blocking(move || {
            let execution = RuntimeProviderExecution::new(
                keyring.as_ref(),
                execution_store.as_ref(),
                profile.as_ref(),
                prohibited.as_ref(),
            );
            execution.preflight_existing_active_key(authority, generation)?;
            execution.apply_pending_terminal_outputs(&application)
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider recovery unavailable".into()))?
        .map(|_| ())
        .map_err(|_| DaemonError::Bootstrap("provider recovery unavailable".into()))
    }
}

impl CanonicalProviderExecutionService for DaemonCanonicalOpenAiService {
    fn execute(
        &self,
        job: CanonicalProviderExecutionJob,
    ) -> gocode_provider::ProviderFuture<
        '_,
        Result<gocode_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>,
    > {
        Box::pin(async move {
            let call = project_call(&self.conversation_store, &job, self.profile.as_ref())?;
            let requested_input_tokens = u64::try_from(self.profile.max_input_bytes())
                .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
            let maximum_usage = ProviderUsage::new(
                requested_input_tokens,
                u64::from(self.profile.max_output_tokens()),
                0,
                0,
            )
            .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
            let max_cost_micros = self
                .profile
                .price_usage_micros(maximum_usage)
                .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
            let coordinator = ProviderDispatchCoordinator::new(
                self.dispatch_store.as_ref(),
                self.execution_store.as_ref(),
                self.adapter.as_ref(),
                self.prohibited_content.as_ref(),
            );
            let outcome = coordinator
                .dispatch(ProviderCoordinatorRequest {
                    call,
                    principal_id: job.context.principal_id.0.clone(),
                    conversation_id: job.started.conversation_id,
                    taskrun_id: job.started.taskrun_id,
                    execution_attempt_id: job.started.attempt_id,
                    profile_digest: self.profile.profile_digest(),
                    pricing_revision_digest: self.profile.pricing_revision_digest(),
                    requested_input_tokens,
                    requested_output_tokens: self.profile.max_output_tokens(),
                    max_cost_micros,
                    currency: self.profile.currency().to_owned(),
                    provider_idempotency_key: provider_idempotency_key(&job),
                })
                .await
                .map_err(|_| CanonicalProviderExecutionError::RejectedBeforeEffect)?;
            let ProviderCoordinatorOutcome::Streaming { binding } = outcome else {
                return Err(match outcome {
                    ProviderCoordinatorOutcome::Uncertain => {
                        CanonicalProviderExecutionError::Uncertain
                    }
                    ProviderCoordinatorOutcome::RejectedBeforeEffect { .. } => {
                        CanonicalProviderExecutionError::RejectedBeforeEffect
                    }
                    ProviderCoordinatorOutcome::Existing { .. } => {
                        CanonicalProviderExecutionError::Conflict
                    }
                    ProviderCoordinatorOutcome::Streaming { .. } => unreachable!(),
                });
            };
            let context = ProviderEventJournalContext {
                attempt_id: binding.attempt_id(),
                fencing_token: binding.fencing_token(),
                call_digest_version: binding.call_digest_version(),
                profile_digest: *binding.profile_digest(),
                runtime_generation: binding.runtime_generation(),
            };
            let execution = RuntimeProviderExecution::new(
                self.keyring.as_ref(),
                self.execution_store.as_ref(),
                self.profile.as_ref(),
                self.prohibited_content.as_ref(),
            );
            execution
                .preflight_existing_active_key(self.runtime_authority_id, self.database_generation)
                .map_err(map_execution_error)?;
            let mut cursor = 0_u64;
            let terminal_disposition;
            loop {
                let item = execution
                    .next_and_commit(
                        self.adapter.as_ref(),
                        &binding.stream_id(),
                        StreamCursor::new(cursor),
                        &context,
                    )
                    .await
                    .map_err(map_execution_error)?;
                if let ProviderStreamEventKind::Finished { disposition, .. } = item.event().kind() {
                    terminal_disposition = *disposition;
                    break;
                }
                cursor = cursor
                    .checked_add(1)
                    .ok_or(CanonicalProviderExecutionError::Conflict)?;
            }
            execution
                .finalize_terminal_output(&context)
                .map_err(map_execution_error)?;
            match terminal_disposition {
                ProviderTerminalDisposition::Completed => {}
                ProviderTerminalDisposition::RemoteFailed => {
                    return Err(CanonicalProviderExecutionError::RemoteFailed);
                }
                ProviderTerminalDisposition::RemoteIncomplete => {
                    return Err(CanonicalProviderExecutionError::RemoteIncomplete);
                }
                ProviderTerminalDisposition::CancelledUncertain => {
                    return Err(CanonicalProviderExecutionError::Uncertain);
                }
            }
            let execution_store = Arc::clone(&self.execution_store);
            let profile = Arc::clone(&self.profile);
            let keyring = Arc::clone(&self.keyring);
            let prohibited = Arc::clone(&self.prohibited_content);
            let application = ConversationProviderTerminalApplication::new(
                self.conversation_store.clone(),
                Arc::clone(&self.conversation_service),
            );
            let attempt_id = binding.attempt_id();
            let authority = self.runtime_authority_id;
            let generation = self.database_generation;
            let applied = tokio::task::spawn_blocking(move || {
                let execution = RuntimeProviderExecution::new(
                    keyring.as_ref(),
                    execution_store.as_ref(),
                    profile.as_ref(),
                    prohibited.as_ref(),
                );
                execution.preflight_existing_active_key(authority, generation)?;
                execution.apply_terminal_output_for_attempt(attempt_id, &application)
            })
            .await
            .map_err(|_| CanonicalProviderExecutionError::Unavailable)?
            .map_err(map_execution_error)?;
            if !applied {
                return Err(CanonicalProviderExecutionError::RemoteFailed);
            }
            let completed = self
                .conversation_store
                .load_text_generation_receipt_by_command(
                    job.context.command_id,
                    &job.context.idempotency_key,
                )
                .map_err(|_| CanonicalProviderExecutionError::Unavailable)?;
            if completed.phase != gocode_application::ports::TextGenerationPhase::Completed
                || completed.conversation_id != job.started.conversation_id
                || completed.taskrun_id != job.started.taskrun_id
                || completed.attempt_id != job.started.attempt_id
            {
                return Err(CanonicalProviderExecutionError::Conflict);
            }
            Ok(completed)
        })
    }
}

fn project_call(
    store: &StoreTransaction,
    job: &CanonicalProviderExecutionJob,
    profile: &OpenAiResponsesTextProfile,
) -> Result<ProviderCall, CanonicalProviderExecutionError> {
    let stream = store
        .load_conversation(job.started.conversation_id)
        .map_err(|_| CanonicalProviderExecutionError::Unavailable)?;
    if stream.current_version != job.started.conversation_version {
        return Err(CanonicalProviderExecutionError::Conflict);
    }
    let mut inputs = Vec::new();
    let mut manifest = Sha256::new();
    for event in &stream.events {
        manifest.update(event.integrity_digest().as_bytes());
        match event.payload() {
            ConversationEvent::UserMessageAppended { text, .. } => inputs.push(
                ProviderTextInput::new(ProviderInputRole::User, text.as_str().to_owned())
                    .map_err(|_| CanonicalProviderExecutionError::Conflict)?,
            ),
            ConversationEvent::AssistantMessageAppended { text, .. } => inputs.push(
                ProviderTextInput::new(ProviderInputRole::Assistant, text.as_str().to_owned())
                    .map_err(|_| CanonicalProviderExecutionError::Conflict)?,
            ),
            ConversationEvent::ConversationCreated { .. }
            | ConversationEvent::ConversationClosed
            | ConversationEvent::GenerationFailed { .. } => {}
        }
    }
    let call_id = ProviderCallId::from_bytes(derived_bytes16(
        b"GOCODE_CANONICAL_PROVIDER_CALL_V1\0",
        job.context.command_id.as_bytes(),
    ));
    ProviderCall::new(
        call_id,
        ModelRef::new(
            ProviderId::new("openai").map_err(|_| CanonicalProviderExecutionError::Conflict)?,
            OPENAI_MODEL_ID,
            OPENAI_MODEL_REVISION,
        )
        .map_err(|_| CanonicalProviderExecutionError::Conflict)?,
        manifest.finalize().into(),
        profile.max_output_tokens(),
        profile.binding_extension(),
    )
    .and_then(|call| call.with_text_inputs(inputs))
    .map(|call| call.with_required_capabilities(vec![ProviderCapability::Streaming]))
    .map_err(|_| CanonicalProviderExecutionError::Conflict)
}

fn provider_idempotency_key(job: &CanonicalProviderExecutionJob) -> String {
    format!(
        "gocode-provider-{}",
        hex::encode(derived_bytes16(
            b"GOCODE_PROVIDER_IDEMPOTENCY_V1\0",
            job.context.command_id.as_bytes(),
        ))
    )
}

fn derived_bytes16(domain: &[u8], input: &[u8]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(input)
        .finalize();
    digest[..16]
        .try_into()
        .expect("SHA-256 prefix has exact length")
}

fn policy_binding_digest(
    activation_identity: [u8; 32],
    profile: &OpenAiResponsesTextProfile,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"GOCODE_PROVIDER_POLICY_BINDING_V1\0")
        .chain_update(activation_identity)
        .chain_update(profile.profile_digest())
        .chain_update(PROVIDER_POLICY_V1_REVISION.to_be_bytes())
        .finalize()
        .into()
}

fn derived_identity(label: &str, binding: [u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(b"GOCODE_PROVIDER_POLICY_ID_V1\0")
        .chain_update(label.as_bytes())
        .chain_update(binding)
        .finalize();
    format!("provider-{label}-{}", hex::encode(&digest[..16]))
}

fn credential_access_policy() -> Result<ProviderCredentialAccessPolicy, DaemonError> {
    let reader = std::env::current_exe()
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    let reader = std::fs::canonicalize(reader)
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    let writer: PathBuf = reader
        .parent()
        .map(|directory| directory.join("gocode"))
        .ok_or_else(|| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    ProviderCredentialAccessPolicy::new(&writer, &reader)
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))
}

#[cfg(target_os = "macos")]
fn native_journal_keyring(authority: [u8; 16]) -> Arc<dyn ProviderJournalKeyring> {
    Arc::new(gocode_secure_store::MacOsKeychainStore::new(hex::encode(
        authority,
    )))
}

#[cfg(not(target_os = "macos"))]
fn native_journal_keyring(_authority: [u8; 16]) -> Arc<dyn ProviderJournalKeyring> {
    Arc::new(gocode_secure_store::StubStore::new())
}

fn unix_seconds() -> Result<u64, DaemonError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .ok_or_else(|| DaemonError::Bootstrap("provider policy clock unavailable".into()))
}

fn map_credential_error(error: SecureStoreError) -> OpenAiCredentialError {
    match error {
        SecureStoreError::ProviderCredentialNotFound => OpenAiCredentialError::Missing,
        _ => OpenAiCredentialError::AccessDenied,
    }
}

const fn map_execution_error(
    error: RuntimeProviderExecutionError,
) -> CanonicalProviderExecutionError {
    match error {
        RuntimeProviderExecutionError::JournalCommitLost
        | RuntimeProviderExecutionError::RecoveryFrozen => {
            CanonicalProviderExecutionError::Uncertain
        }
        RuntimeProviderExecutionError::PolicyDenied => {
            CanonicalProviderExecutionError::PolicyDenied
        }
        RuntimeProviderExecutionError::ApplicationConflict
        | RuntimeProviderExecutionError::TerminalRejected
        | RuntimeProviderExecutionError::JournalCorrupt => {
            CanonicalProviderExecutionError::Conflict
        }
        RuntimeProviderExecutionError::KeyRetentionUnsupported
        | RuntimeProviderExecutionError::JournalKeyUnavailable
        | RuntimeProviderExecutionError::PersistenceUnavailable
        | RuntimeProviderExecutionError::AdapterStreamUnavailable
        | RuntimeProviderExecutionError::PricingUnavailable
        | RuntimeProviderExecutionError::ApplicationUnavailable => {
            CanonicalProviderExecutionError::Unavailable
        }
    }
}
