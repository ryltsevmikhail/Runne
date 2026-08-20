use core::fmt::{self, Write as _};
use std::sync::{Arc, Mutex};

use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextServiceError,
};
use runne_application::ports::{
    ApplicationCommandContext, TextGenerationPhase, TextGenerationReceipt,
};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use runne_application::provider::{
    ProviderEncryptedPayload, ProviderExecutionError, ProviderExecutionStore,
    ProviderJournalAppendOutcome, ProviderJournalAppendRequest, ProviderJournalKeyBinding,
    ProviderPollRequest, ProviderTerminalCommitOutcome, ProviderTerminalOutboxRecord,
    ProviderTerminalPricingBinding, ProviderRecoveryObserver,
};
use runne_domain::message::MessageText;
use runne_provider::{
    DispatchAttemptId, ProviderCallDigestVersion, ProviderFinishReason, ProviderPort,
    ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId, ProviderStreamItem,
    ProviderStreamValidator, ProviderTerminalDisposition, ProviderUsage, StreamCursor,
};
pub use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError,
};
use runne_secure_store::{
    ProviderJournalKeyMaterial, ProviderJournalKeyRef, ProviderJournalKeyStatus,
    ProviderJournalKeyring, SecureStoreError,
};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::provider_redaction::{
    PreJournalProviderEvent, ProviderEventRedaction,
};

const PROVIDER_JOURNAL_AAD_V1: &[u8] = b"GOCODE_PROVIDER_JOURNAL_AAD_V1\0";
const PROVIDER_OUTBOX_AAD_V1: &[u8] = b"GOCODE_PROVIDER_OUTBOX_AAD_V1\0";
const PROVIDER_OUTBOX_ID_V1: &[u8] = b"GOCODE_PROVIDER_OUTBOX_ID_V1\0";
const PROVIDER_SETTLEMENT_V2: &[u8] = b"GOCODE_PROVIDER_SETTLEMENT_V2\0";
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

/// Opaque runtime-owned terminal settlement command.
///
/// Fields have no public constructor or setters. Persistence adapters can
/// inspect an instance supplied by the runtime, but safe code outside this
/// module cannot manufacture terminal usage, charge, outbox identity or
/// settlement evidence.
///
/// ```compile_fail
/// use runne_runtime::provider_execution::ProviderTerminalCommitRequest;
///
/// fn forge() -> ProviderTerminalCommitRequest {
///     ProviderTerminalCommitRequest {}
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ProviderTerminalCommitRequest {
    outbox_id: [u8; 16],
    attempt_id: DispatchAttemptId,
    fencing_token: u64,
    terminal_sequence: u64,
    call_digest_version: ProviderCallDigestVersion,
    key: ProviderJournalKeyBinding,
    encrypted_output: Option<ProviderEncryptedPayload>,
    runtime_generation: u64,
    profile_digest: [u8; 32],
    usage: ProviderUsage,
    usage_unavailable: bool,
    disposition: ProviderTerminalDisposition,
    charge_micros: u64,
    currency: String,
    settlement_digest: [u8; 32],
    application_idempotency_key: String,
}

impl ProviderTerminalCommitRequest {
    /// Constructs deliberately caller-selected evidence for persistence
    /// adapter tests. This API is absent unless the explicit test-support
    /// feature is enabled.
    #[cfg(feature = "provider-terminal-test-support")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn forge_for_tests(
        outbox_id: [u8; 16],
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        terminal_sequence: u64,
        call_digest_version: ProviderCallDigestVersion,
        key: ProviderJournalKeyBinding,
        encrypted_output: ProviderEncryptedPayload,
        runtime_generation: u64,
        profile_digest: [u8; 32],
        usage: ProviderUsage,
        charge_micros: u64,
        currency: String,
        settlement_digest: [u8; 32],
        application_idempotency_key: String,
    ) -> Self {
        Self {
            outbox_id,
            attempt_id,
            fencing_token,
            terminal_sequence,
            call_digest_version,
            key,
            encrypted_output: Some(encrypted_output),
            runtime_generation,
            profile_digest,
            usage,
            usage_unavailable: false,
            disposition: ProviderTerminalDisposition::Completed,
            charge_micros,
            currency,
            settlement_digest,
            application_idempotency_key,
        }
    }

    /// Returns the stable runtime-derived outbox identity.
    #[must_use]
    pub const fn outbox_id(&self) -> &[u8; 16] {
        &self.outbox_id
    }

    /// Returns the durable provider attempt.
    #[must_use]
    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.attempt_id
    }

    /// Returns the current runtime-issued fencing token.
    #[must_use]
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Returns the authenticated terminal journal sequence.
    #[must_use]
    pub const fn terminal_sequence(&self) -> u64 {
        self.terminal_sequence
    }

    /// Returns the prepared call digest domain.
    #[must_use]
    pub const fn call_digest_version(&self) -> ProviderCallDigestVersion {
        self.call_digest_version
    }

    /// Returns the journal-key binding used for terminal ciphertext.
    #[must_use]
    pub const fn key(&self) -> ProviderJournalKeyBinding {
        self.key
    }

    /// Returns the encrypted recoverable terminal output.
    #[must_use]
    pub const fn encrypted_output(&self) -> Option<&ProviderEncryptedPayload> {
        self.encrypted_output.as_ref()
    }

    /// Returns the exact runtime generation.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Returns the exact provider profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }

    /// Returns authenticated and validated provider usage.
    #[must_use]
    pub const fn usage(&self) -> ProviderUsage {
        self.usage
    }

    /// Returns whether exact remote usage was unavailable and the stored
    /// values therefore represent the full admitted reservation.
    #[must_use]
    pub const fn usage_unavailable(&self) -> bool {
        self.usage_unavailable
    }

    /// Returns the authenticated remote terminal disposition.
    #[must_use]
    pub const fn disposition(&self) -> ProviderTerminalDisposition {
        self.disposition
    }

    /// Returns the exact fixed-point charge.
    #[must_use]
    pub const fn charge_micros(&self) -> u64 {
        self.charge_micros
    }

    /// Returns the canonical settlement currency.
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Returns the runtime-derived settlement digest.
    #[must_use]
    pub const fn settlement_digest(&self) -> &[u8; 32] {
        &self.settlement_digest
    }

    /// Returns the stable Conversation completion identity.
    #[must_use]
    pub fn application_idempotency_key(&self) -> &str {
        &self.application_idempotency_key
    }
}

/// Runtime-only persistence boundary for one opaque terminal settlement.
pub trait ProviderTerminalPersistence: Send + Sync {
    /// Atomically settles accounting/reservations and creates the outbox.
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError>;
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
