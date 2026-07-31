//! Runtime-owned encrypted provider stream journal and terminal outbox.

use core::fmt::{self, Write as _};
use std::sync::Mutex;

use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_application::provider::{
    ProviderEncryptedPayload, ProviderExecutionError, ProviderExecutionStore,
    ProviderJournalAppendOutcome, ProviderJournalAppendRequest, ProviderJournalKeyBinding,
    ProviderPollRequest, ProviderTerminalCommitOutcome, ProviderTerminalCommitRequest,
    ProviderTerminalOutboxRecord, ProviderTerminalPricingBinding,
};
use gocode_provider::{
    DispatchAttemptId, ProviderCallDigestVersion, ProviderPort, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamId, ProviderStreamItem, ProviderStreamValidator,
    ProviderUsage, StreamCursor,
};
use gocode_secure_store::{
    ProviderJournalKeyMaterial, ProviderJournalKeyRef, ProviderJournalKeyring, SecureStoreError,
};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const PROVIDER_JOURNAL_AAD_V1: &[u8] = b"GOCODE_PROVIDER_JOURNAL_AAD_V1\0";
const PROVIDER_OUTBOX_AAD_V1: &[u8] = b"GOCODE_PROVIDER_OUTBOX_AAD_V1\0";
const PROVIDER_OUTBOX_ID_V1: &[u8] = b"GOCODE_PROVIDER_OUTBOX_ID_V1\0";
const PROVIDER_SETTLEMENT_V1: &[u8] = b"GOCODE_PROVIDER_SETTLEMENT_V1\0";
const MAX_PROVIDER_ASSEMBLED_OUTPUT_BYTES: usize = 4_194_288;

/// Exact non-secret binding for one normalized provider stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderEventJournalContext {
    /// Durable provider dispatch attempt.
    pub attempt_id: DispatchAttemptId,
    /// Current runtime-issued fencing token.
    pub fencing_token: u64,
    /// Exact prepared call digest contract.
    pub call_digest_version: ProviderCallDigestVersion,
    /// Exact immutable provider profile.
    pub profile_digest: [u8; 32],
    /// Current runtime generation.
    pub runtime_generation: u64,
}

/// Runtime-trusted result of immutable pricing for exact journal usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPricedUsage {
    charge_micros: u64,
    currency: String,
}

impl ProviderPricedUsage {
    /// Constructs a bounded uppercase-currency price.
    pub fn new(charge_micros: u64, currency: String) -> Result<Self, ProviderTerminalPricingError> {
        if charge_micros > i64::MAX as u64
            || currency.len() != 3
            || !currency.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(ProviderTerminalPricingError::InvalidQuote);
        }
        Ok(Self {
            charge_micros,
            currency,
        })
    }
}

/// Closed immutable-pricing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderTerminalPricingError {
    /// Pricing revision is unavailable.
    #[error("provider pricing revision is unavailable")]
    Unavailable,
    /// Pricing returned malformed or unbounded values.
    #[error("provider pricing quote is invalid")]
    InvalidQuote,
}

/// Runtime-owned immutable pricing boundary.
pub trait ProviderTerminalPricing: Send + Sync {
    /// Prices exact authenticated usage under the admitted immutable revision.
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError>;
}

/// Decrypted terminal output retained only in runtime memory.
pub struct RecoveredProviderTerminalOutput {
    record: ProviderTerminalOutboxRecord,
    output: Zeroizing<Vec<u8>>,
}

impl RecoveredProviderTerminalOutput {
    /// Returns non-secret durable outbox metadata.
    pub const fn record(&self) -> &ProviderTerminalOutboxRecord {
        &self.record
    }

    /// Returns decrypted output bytes in runtime memory.
    pub fn output(&self) -> &[u8] {
        &self.output
    }
}

impl fmt::Debug for RecoveredProviderTerminalOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredProviderTerminalOutput")
            .field("record", &self.record)
            .field("output_len", &self.output.len())
            .finish()
    }
}

/// Typed runtime provider execution failure with no key/plaintext material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuntimeProviderExecutionError {
    /// Native secure-store key was absent or had a different binding.
    #[error("provider journal key is unavailable")]
    JournalKeyUnavailable,
    /// Secure-store backend cannot retain recovery key versions.
    #[error("provider journal key retention is unsupported")]
    KeyRetentionUnsupported,
    /// Ciphertext, AAD, sequence or normalized event bytes failed validation.
    #[error("provider journal recovery failed closed")]
    JournalCorrupt,
    /// Durable journal/outbox commit was unavailable.
    #[error("provider journal persistence is unavailable")]
    PersistenceUnavailable,
    /// Adapter stream polling failed before a new event was accepted.
    #[error("provider stream polling failed")]
    AdapterStreamUnavailable,
    /// Provider bytes arrived but their local commit could not be proven.
    #[error("provider journal commit was lost and the attempt is uncertain")]
    JournalCommitLost,
    /// Attempt generation/state no longer permits automatic progression.
    #[error("provider execution recovery is frozen")]
    RecoveryFrozen,
    /// Terminal usage/accounting/outbox transaction was rejected.
    #[error("provider terminal transaction was rejected")]
    TerminalRejected,
    /// Terminal output was prohibited or policy state was unavailable.
    #[error("provider terminal output was denied by policy")]
    PolicyDenied,
    /// Exact immutable pricing could not be resolved.
    #[error("provider terminal pricing is unavailable")]
    PricingUnavailable,
    /// Authoritative Conversation completion is temporarily unavailable.
    #[error("provider terminal application is unavailable")]
    ApplicationUnavailable,
    /// Authoritative Conversation completion conflicts with the outbox.
    #[error("provider terminal application conflicts")]
    ApplicationConflict,
}

/// Closed errors from authoritative terminal outbox application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderTerminalApplicationError {
    /// The application service is temporarily unavailable and may be retried.
    #[error("terminal application is unavailable")]
    Unavailable,
    /// The stable completion identity conflicts with authoritative state.
    #[error("terminal application conflicts")]
    Conflict,
}

/// Idempotent authoritative completion boundary for terminal provider output.
///
/// Implementations must use `record.application_idempotency_key` as the exact
/// command identity. A replay after application commit but before outbox
/// acknowledgement must return the original non-zero receipt digest.
pub trait ProviderTerminalOutboxApplication: Send + Sync {
    /// Applies one policy-approved plaintext output in runtime memory.
    fn complete_provider_terminal(
        &self,
        record: &ProviderTerminalOutboxRecord,
        output: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError>;
}

/// Runtime service that owns journal keys, AEAD and commit-before-next-poll.
pub struct RuntimeProviderExecution<'a, K, S> {
    keyring: &'a K,
    store: &'a S,
    random: SystemRandom,
    active_key: Mutex<Option<ProviderJournalKeyBinding>>,
}

impl<'a, K, S> RuntimeProviderExecution<'a, K, S>
where
    K: ProviderJournalKeyring,
    S: ProviderExecutionStore,
{
    /// Constructs an execution service from inward-facing secure/store ports.
    pub fn new(keyring: &'a K, store: &'a S) -> Self {
        Self {
            keyring,
            store,
            random: SystemRandom::new(),
            active_key: Mutex::new(None),
        }
    }

    /// Creates, stores and activates one random 32-byte journal key.
    ///
    /// Secure storage happens before database activation, so an interrupted
    /// rotation can at worst leave unreferenced key material, never a durable
    /// ciphertext reference without its key.
    pub fn create_and_activate_key(
        &self,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        key_version: u64,
    ) -> Result<ProviderJournalKeyBinding, RuntimeProviderExecutionError> {
        if !self.keyring.retains_multiple_provider_journal_keys() {
            return Err(RuntimeProviderExecutionError::KeyRetentionUnsupported);
        }
        let key_id = self.random_nonzero::<16>()?;
        let key_bytes = self.random_nonzero::<32>()?;
        let key_ref = ProviderJournalKeyRef::new(
            key_id,
            key_version,
            runtime_authority_id,
            database_generation,
        )
        .map_err(map_secure_store_error)?;
        let material =
            ProviderJournalKeyMaterial::new(key_ref, key_bytes).map_err(map_secure_store_error)?;
        self.keyring
            .store_provider_journal_key(&material)
            .map_err(map_secure_store_error)?;
        let binding = binding_from_secure_ref(key_ref)?;
        self.store
            .activate_journal_key(binding)
            .map_err(map_execution_error)?;
        *self
            .active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)? = Some(binding);
        Ok(binding)
    }

    /// Rebinds this process to an already active durable key after restart.
    pub fn use_existing_active_key(
        &self,
        binding: ProviderJournalKeyBinding,
    ) -> Result<(), RuntimeProviderExecutionError> {
        self.load_key(binding)?;
        *self
            .active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)? = Some(binding);
        Ok(())
    }

    /// Encrypts and commits one normalized event.
    fn commit_polled_event(
        &self,
        context: &ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<ProviderJournalAppendOutcome, RuntimeProviderExecutionError> {
        if event.sequence() == u64::MAX {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        let key = self.current_key()?;
        let material = self.load_key(key)?;
        let event_kind = event_kind_code(event.kind());
        let terminal = matches!(event.kind(), ProviderStreamEventKind::Finished { .. });
        let plaintext =
            serde_json::to_vec(event).map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
        let aad = event_aad(context, key, event.sequence(), event_kind, terminal);
        let encrypted = self.seal(&material, &aad, &plaintext)?;
        self.store
            .append_encrypted_event(&ProviderJournalAppendRequest {
                attempt_id: context.attempt_id,
                fencing_token: context.fencing_token,
                sequence: event.sequence(),
                event_kind,
                terminal,
                call_digest_version: context.call_digest_version,
                profile_digest: context.profile_digest,
                runtime_generation: context.runtime_generation,
                key,
                encrypted,
            })
            .map_err(map_execution_error)
    }

    /// Polls exactly one adapter item and durably journals it before returning.
    ///
    /// If local commit cannot be proven after provider bytes arrive, the
    /// attempt is marked `Uncertain`; the caller receives no item to advance.
    pub async fn next_and_commit<P: ProviderPort>(
        &self,
        provider: &P,
        stream_id: &ProviderStreamId,
        cursor: StreamCursor,
        context: &ProviderEventJournalContext,
    ) -> Result<ProviderStreamItem, RuntimeProviderExecutionError> {
        self.store
            .begin_provider_poll(&ProviderPollRequest {
                attempt_id: context.attempt_id,
                fencing_token: context.fencing_token,
                cursor: cursor.sequence(),
                profile_digest: context.profile_digest,
                runtime_generation: context.runtime_generation,
            })
            .map_err(map_execution_error)?;
        let item = match provider.next(stream_id, cursor).await {
            Ok(item) => item,
            Err(_) => {
                self.store
                    .mark_execution_uncertain(context.attempt_id, context.fencing_token)
                    .map_err(|_| RuntimeProviderExecutionError::JournalCommitLost)?;
                return Err(RuntimeProviderExecutionError::AdapterStreamUnavailable);
            }
        };
        if self.commit_polled_event(context, item.event()).is_err() {
            self.store
                .mark_execution_uncertain(context.attempt_id, context.fencing_token)
                .map_err(|_| RuntimeProviderExecutionError::JournalCommitLost)?;
            return Err(RuntimeProviderExecutionError::JournalCommitLost);
        }
        Ok(item)
    }

    /// Decrypts and validates every exact committed event for recovery.
    pub fn recover_events(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderStreamEvent>, RuntimeProviderExecutionError> {
        let encrypted = self
            .store
            .load_encrypted_events(attempt_id)
            .map_err(map_execution_error)?;
        encrypted
            .into_iter()
            .map(|record| {
                let material = self.load_key(record.key)?;
                let context = ProviderEventJournalContext {
                    attempt_id: record.attempt_id,
                    fencing_token: record.fencing_token,
                    call_digest_version: record.call_digest_version,
                    profile_digest: record.profile_digest,
                    runtime_generation: record.runtime_generation,
                };
                let aad = event_aad(
                    &context,
                    record.key,
                    record.sequence,
                    record.event_kind,
                    record.terminal,
                );
                let plaintext = Zeroizing::new(open_payload(&material, &aad, &record.encrypted)?);
                let event: ProviderStreamEvent = serde_json::from_slice(&plaintext)
                    .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
                if event.sequence() != record.sequence
                    || event_kind_code(event.kind()) != record.event_kind
                    || matches!(event.kind(), ProviderStreamEventKind::Finished { .. })
                        != record.terminal
                {
                    return Err(RuntimeProviderExecutionError::JournalCorrupt);
                }
                Ok(event)
            })
            .collect()
    }

    /// Reconstructs terminal output/usage from the authenticated journal,
    /// applies prohibited-content policy and immutable pricing, then commits
    /// the encrypted accounting/outbox transaction.
    pub fn finalize_terminal_output<P: ProviderTerminalPricing>(
        &self,
        context: &ProviderEventJournalContext,
        pricing: &P,
        prohibited_content: &dyn ProhibitedContentPort,
    ) -> Result<ProviderTerminalCommitOutcome, RuntimeProviderExecutionError> {
        let pricing_binding = self
            .store
            .load_terminal_pricing_binding(context.attempt_id)
            .map_err(map_execution_error)?;
        let events = self.recover_events(context.attempt_id)?;
        let assembled = assemble_terminal_stream(&events)?;
        match prohibited_content.inspect(
            CanonicalContentBoundary::CanonicalMutation,
            &assembled.output,
        ) {
            Ok(ContentDisposition::Allowed { .. }) => {}
            Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
                return Err(RuntimeProviderExecutionError::PolicyDenied);
            }
        }
        let priced = pricing
            .price_terminal_usage(
                pricing_binding.pricing_revision_digest(),
                &context.profile_digest,
                assembled.usage,
            )
            .map_err(|_| RuntimeProviderExecutionError::PricingUnavailable)?;
        if priced.currency != pricing_binding.currency() {
            return Err(RuntimeProviderExecutionError::PricingUnavailable);
        }
        let terminal = self
            .store
            .load_encrypted_events(context.attempt_id)
            .map_err(map_execution_error)?
            .into_iter()
            .find(|record| record.sequence == assembled.terminal_sequence && record.terminal)
            .ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
        if terminal.call_digest_version != context.call_digest_version
            || terminal.profile_digest != context.profile_digest
            || terminal.runtime_generation != context.runtime_generation
        {
            return Err(RuntimeProviderExecutionError::TerminalRejected);
        }
        let outbox_id = stable_outbox_id(context, assembled.terminal_sequence);
        let settlement_digest = settlement_digest(
            context,
            &pricing_binding,
            assembled.terminal_sequence,
            &assembled.output,
            assembled.usage,
            priced.charge_micros,
            &priced.currency,
        );
        let application_idempotency_key = terminal_application_key(context.attempt_id);
        let material = self.load_key(terminal.key)?;
        let aad = outbox_aad(
            context,
            terminal.key,
            assembled.terminal_sequence,
            outbox_id,
        );
        let encrypted_output = self.seal(&material, &aad, &assembled.output)?;
        self.store
            .commit_terminal(&ProviderTerminalCommitRequest {
                outbox_id,
                attempt_id: context.attempt_id,
                fencing_token: context.fencing_token,
                terminal_sequence: assembled.terminal_sequence,
                call_digest_version: context.call_digest_version,
                key: terminal.key,
                encrypted_output,
                runtime_generation: context.runtime_generation,
                profile_digest: context.profile_digest,
                usage: assembled.usage,
                charge_micros: priced.charge_micros,
                currency: priced.currency,
                settlement_digest,
                application_idempotency_key,
            })
            .map_err(map_execution_error)
    }

    /// Loads and decrypts pending terminal outputs for idempotent application.
    pub fn recover_pending_terminal_outputs(
        &self,
    ) -> Result<Vec<RecoveredProviderTerminalOutput>, RuntimeProviderExecutionError> {
        self.store
            .pending_terminal_outbox()
            .map_err(map_execution_error)?
            .into_iter()
            .map(|record| {
                let material = self.load_key(record.key)?;
                let context = ProviderEventJournalContext {
                    attempt_id: record.attempt_id,
                    fencing_token: record.fencing_token,
                    call_digest_version: record.call_digest_version,
                    profile_digest: record.profile_digest,
                    runtime_generation: record.runtime_generation,
                };
                let aad = outbox_aad(
                    &context,
                    record.key,
                    record.terminal_sequence,
                    record.outbox_id,
                );
                let output =
                    Zeroizing::new(open_payload(&material, &aad, &record.encrypted_output)?);
                Ok(RecoveredProviderTerminalOutput { record, output })
            })
            .collect()
    }

    /// Marks exact authoritative Conversation receipt and settles the attempt.
    pub fn acknowledge_terminal_output(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), RuntimeProviderExecutionError> {
        self.store
            .acknowledge_terminal_outbox(outbox_id, receipt_digest)
            .map_err(map_execution_error)
    }

    /// Applies every pending terminal output through an idempotent
    /// authoritative application boundary, then durably acknowledges its
    /// exact receipt.
    pub fn apply_pending_terminal_outputs<A: ProviderTerminalOutboxApplication>(
        &self,
        application: &A,
    ) -> Result<usize, RuntimeProviderExecutionError> {
        let pending = self.recover_pending_terminal_outputs()?;
        let mut applied = 0_usize;
        for recovered in pending {
            let receipt_digest = application
                .complete_provider_terminal(recovered.record(), recovered.output())
                .map_err(|error| match error {
                    ProviderTerminalApplicationError::Unavailable => {
                        RuntimeProviderExecutionError::ApplicationUnavailable
                    }
                    ProviderTerminalApplicationError::Conflict => {
                        RuntimeProviderExecutionError::ApplicationConflict
                    }
                })?;
            if receipt_digest == [0; 32] {
                return Err(RuntimeProviderExecutionError::ApplicationConflict);
            }
            self.acknowledge_terminal_output(recovered.record().outbox_id, receipt_digest)?;
            applied = applied
                .checked_add(1)
                .ok_or(RuntimeProviderExecutionError::ApplicationConflict)?;
        }
        Ok(applied)
    }

    fn current_key(&self) -> Result<ProviderJournalKeyBinding, RuntimeProviderExecutionError> {
        self.active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)?
            .ok_or(RuntimeProviderExecutionError::JournalKeyUnavailable)
    }

    fn load_key(
        &self,
        binding: ProviderJournalKeyBinding,
    ) -> Result<ProviderJournalKeyMaterial, RuntimeProviderExecutionError> {
        self.keyring
            .load_provider_journal_key(secure_ref_from_binding(binding)?)
            .map_err(map_secure_store_error)
    }

    fn random_nonzero<const N: usize>(&self) -> Result<[u8; N], RuntimeProviderExecutionError> {
        loop {
            let mut bytes = [0_u8; N];
            self.random
                .fill(&mut bytes)
                .map_err(|_| RuntimeProviderExecutionError::JournalKeyUnavailable)?;
            if bytes != [0; N] {
                return Ok(bytes);
            }
        }
    }

    fn seal(
        &self,
        material: &ProviderJournalKeyMaterial,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<ProviderEncryptedPayload, RuntimeProviderExecutionError> {
        let nonce = self.random_nonzero::<12>()?;
        seal_payload_with_nonce(material, nonce, aad, plaintext)
    }
}

struct AssembledTerminal {
    output: Zeroizing<Vec<u8>>,
    usage: ProviderUsage,
    terminal_sequence: u64,
}

fn assemble_terminal_stream(
    events: &[ProviderStreamEvent],
) -> Result<AssembledTerminal, RuntimeProviderExecutionError> {
    let mut validator = ProviderStreamValidator::default();
    let mut output = Zeroizing::new(Vec::new());
    let mut usage = None;
    let mut terminal_sequence = None;
    for event in events {
        validator
            .accept(event)
            .map_err(|_| RuntimeProviderExecutionError::TerminalRejected)?;
        match event.kind() {
            ProviderStreamEventKind::Started => {}
            ProviderStreamEventKind::TextDelta { text } => {
                let current_len = output.len();
                let next_len = current_len
                    .checked_add(text.len())
                    .filter(|length| *length <= MAX_PROVIDER_ASSEMBLED_OUTPUT_BYTES)
                    .ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
                output.reserve(next_len - current_len);
                output.extend_from_slice(text.as_bytes());
            }
            ProviderStreamEventKind::Usage { usage: exact_usage } => usage = Some(*exact_usage),
            ProviderStreamEventKind::ToolCallRequested { .. } => {
                return Err(RuntimeProviderExecutionError::TerminalRejected);
            }
            ProviderStreamEventKind::Finished { .. } => terminal_sequence = Some(event.sequence()),
        }
    }
    let terminal_sequence =
        terminal_sequence.ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
    if events.last().map(ProviderStreamEvent::sequence) != Some(terminal_sequence) {
        return Err(RuntimeProviderExecutionError::TerminalRejected);
    }
    Ok(AssembledTerminal {
        output,
        usage: usage.ok_or(RuntimeProviderExecutionError::TerminalRejected)?,
        terminal_sequence,
    })
}

fn stable_outbox_id(context: &ProviderEventJournalContext, terminal_sequence: u64) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_OUTBOX_ID_V1);
    hasher.update(context.attempt_id.as_bytes());
    hasher.update(context.fencing_token.to_be_bytes());
    hasher.update(context.runtime_generation.to_be_bytes());
    hasher.update(terminal_sequence.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    identity
}

fn terminal_application_key(attempt_id: DispatchAttemptId) -> String {
    let mut key = String::with_capacity(53);
    key.push_str("provider-terminal-v1:");
    for byte in attempt_id.as_bytes() {
        let _ = write!(&mut key, "{byte:02x}");
    }
    key
}

#[allow(clippy::too_many_arguments)]
fn settlement_digest(
    context: &ProviderEventJournalContext,
    pricing: &ProviderTerminalPricingBinding,
    terminal_sequence: u64,
    output: &[u8],
    usage: ProviderUsage,
    charge_micros: u64,
    currency: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_SETTLEMENT_V1);
    hasher.update(context.attempt_id.as_bytes());
    hasher.update(context.fencing_token.to_be_bytes());
    hasher.update(context.runtime_generation.to_be_bytes());
    hasher.update(context.profile_digest);
    hasher.update(pricing.pricing_revision_digest());
    hasher.update(terminal_sequence.to_be_bytes());
    hasher.update(Sha256::digest(output));
    hasher.update(usage.input_tokens().to_be_bytes());
    hasher.update(usage.output_tokens().to_be_bytes());
    hasher.update(usage.cached_input_tokens().to_be_bytes());
    hasher.update(usage.reasoning_output_tokens().to_be_bytes());
    hasher.update(charge_micros.to_be_bytes());
    hasher.update(currency.as_bytes());
    hasher.finalize().into()
}

fn seal_payload_with_nonce(
    material: &ProviderJournalKeyMaterial,
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<ProviderEncryptedPayload, RuntimeProviderExecutionError> {
    let mut ciphertext = plaintext.to_vec();
    material.with_bytes(|bytes| {
        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
            .map_err(|_| RuntimeProviderExecutionError::JournalKeyUnavailable)?;
        LessSafeKey::new(unbound)
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)
    })?;
    ProviderEncryptedPayload::new(
        nonce,
        ciphertext,
        u64::try_from(plaintext.len())
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?,
        Sha256::digest(plaintext).into(),
    )
    .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)
}

fn open_payload(
    material: &ProviderJournalKeyMaterial,
    aad: &[u8],
    encrypted: &ProviderEncryptedPayload,
) -> Result<Vec<u8>, RuntimeProviderExecutionError> {
    let mut plaintext = encrypted.ciphertext().to_vec();
    let opened_len = material.with_bytes(|bytes| {
        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
            .map_err(|_| RuntimeProviderExecutionError::JournalKeyUnavailable)?;
        let opened = LessSafeKey::new(unbound)
            .open_in_place(
                Nonce::assume_unique_for_key(*encrypted.nonce()),
                Aad::from(aad),
                &mut plaintext,
            )
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
        Ok::<usize, RuntimeProviderExecutionError>(opened.len())
    })?;
    plaintext.truncate(opened_len);
    if plaintext.len()
        != usize::try_from(encrypted.plaintext_len())
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?
        || Sha256::digest(&plaintext).as_slice() != encrypted.plaintext_digest()
    {
        return Err(RuntimeProviderExecutionError::JournalCorrupt);
    }
    Ok(plaintext)
}

fn event_aad(
    context: &ProviderEventJournalContext,
    key: ProviderJournalKeyBinding,
    sequence: u64,
    event_kind: u8,
    terminal: bool,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(192);
    aad.extend_from_slice(PROVIDER_JOURNAL_AAD_V1);
    push_common_aad(&mut aad, context, key, sequence);
    aad.push(event_kind);
    aad.push(u8::from(terminal));
    aad
}

fn outbox_aad(
    context: &ProviderEventJournalContext,
    key: ProviderJournalKeyBinding,
    terminal_sequence: u64,
    outbox_id: [u8; 16],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(208);
    aad.extend_from_slice(PROVIDER_OUTBOX_AAD_V1);
    push_common_aad(&mut aad, context, key, terminal_sequence);
    aad.extend_from_slice(&outbox_id);
    aad
}

fn push_common_aad(
    aad: &mut Vec<u8>,
    context: &ProviderEventJournalContext,
    key: ProviderJournalKeyBinding,
    sequence: u64,
) {
    aad.extend_from_slice(context.attempt_id.as_bytes());
    aad.extend_from_slice(&context.fencing_token.to_be_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&key.key_id());
    aad.extend_from_slice(&key.key_version().to_be_bytes());
    aad.extend_from_slice(&key.runtime_authority_id());
    aad.extend_from_slice(&key.database_generation().to_be_bytes());
    aad.push(match context.call_digest_version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    });
    aad.extend_from_slice(&context.profile_digest);
    aad.extend_from_slice(&context.runtime_generation.to_be_bytes());
}

fn event_kind_code(kind: &ProviderStreamEventKind) -> u8 {
    match kind {
        ProviderStreamEventKind::Started => 1,
        ProviderStreamEventKind::TextDelta { .. } => 2,
        ProviderStreamEventKind::Usage { .. } => 3,
        ProviderStreamEventKind::ToolCallRequested { .. } => 4,
        ProviderStreamEventKind::Finished { .. } => 5,
    }
}

fn secure_ref_from_binding(
    binding: ProviderJournalKeyBinding,
) -> Result<ProviderJournalKeyRef, RuntimeProviderExecutionError> {
    ProviderJournalKeyRef::new(
        binding.key_id(),
        binding.key_version(),
        binding.runtime_authority_id(),
        binding.database_generation(),
    )
    .map_err(map_secure_store_error)
}

fn binding_from_secure_ref(
    key_ref: ProviderJournalKeyRef,
) -> Result<ProviderJournalKeyBinding, RuntimeProviderExecutionError> {
    ProviderJournalKeyBinding::new(
        key_ref.key_id(),
        key_ref.version(),
        key_ref.runtime_authority_id(),
        key_ref.database_generation(),
    )
    .map_err(map_execution_error)
}

fn map_secure_store_error(error: SecureStoreError) -> RuntimeProviderExecutionError {
    match error {
        SecureStoreError::RetentionUnsupported => {
            RuntimeProviderExecutionError::KeyRetentionUnsupported
        }
        _ => RuntimeProviderExecutionError::JournalKeyUnavailable,
    }
}

fn map_execution_error(error: ProviderExecutionError) -> RuntimeProviderExecutionError {
    match error {
        ProviderExecutionError::JournalKeyUnavailable => {
            RuntimeProviderExecutionError::JournalKeyUnavailable
        }
        ProviderExecutionError::JournalCorrupt
        | ProviderExecutionError::NonceReuse
        | ProviderExecutionError::SequenceMismatch => RuntimeProviderExecutionError::JournalCorrupt,
        ProviderExecutionError::StaleGeneration
        | ProviderExecutionError::AttemptUncertain
        | ProviderExecutionError::PollNotArmed => RuntimeProviderExecutionError::RecoveryFrozen,
        ProviderExecutionError::TerminalConflict
        | ProviderExecutionError::ReservationMismatch
        | ProviderExecutionError::OutboxConflict => RuntimeProviderExecutionError::TerminalRejected,
        ProviderExecutionError::StoreUnavailable => {
            RuntimeProviderExecutionError::PersistenceUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_aad_database_generation_and_ciphertext_fail_authentication() {
        let key_ref = ProviderJournalKeyRef::new([1; 16], 1, [2; 16], 3).unwrap();
        let material = ProviderJournalKeyMaterial::new(key_ref, [4; 32]).unwrap();
        let context = ProviderEventJournalContext {
            attempt_id: DispatchAttemptId::from_bytes([5; 16]),
            fencing_token: 6,
            call_digest_version: ProviderCallDigestVersion::V2,
            profile_digest: [7; 32],
            runtime_generation: 8,
        };
        let key = binding_from_secure_ref(key_ref).unwrap();
        let aad = event_aad(&context, key, 0, 2, false);
        let encrypted =
            seal_payload_with_nonce(&material, [9; 12], &aad, b"authenticated-event").unwrap();
        assert_eq!(
            open_payload(
                &material,
                &event_aad(&context, key, 0, 3, false),
                &encrypted,
            ),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );

        let wrong_generation = ProviderJournalKeyBinding::new([1; 16], 1, [2; 16], 4).unwrap();
        assert_eq!(
            open_payload(
                &material,
                &event_aad(&context, wrong_generation, 0, 2, false),
                &encrypted,
            ),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );

        let wrong_fence = ProviderEventJournalContext {
            fencing_token: context.fencing_token + 1,
            ..context
        };
        assert_eq!(
            open_payload(
                &material,
                &event_aad(&wrong_fence, key, 0, 2, false),
                &encrypted,
            ),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );

        let mut corrupt = encrypted.clone();
        let mut bytes = corrupt.ciphertext().to_vec();
        bytes[0] ^= 1;
        corrupt = ProviderEncryptedPayload::new(
            *corrupt.nonce(),
            bytes,
            corrupt.plaintext_len(),
            *corrupt.plaintext_digest(),
        )
        .unwrap();
        assert_eq!(
            open_payload(&material, &aad, &corrupt),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );
    }
}
