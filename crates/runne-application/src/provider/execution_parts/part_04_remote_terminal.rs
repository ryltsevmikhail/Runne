/// Factual remote response outcome, separate from local cancellation uncertainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRemoteTerminalDisposition {
    /// The response completed successfully.
    Completed,
    /// The provider reported a failed response.
    Failed,
    /// The provider reported an incomplete response.
    Incomplete,
    /// The provider confirmed remote cancellation.
    Cancelled,
}

/// Canonical values whose settlement digest is checked against the authenticated artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderRemoteTerminalSettlementDigestCandidate<'a> {
    pub status: ProviderRemoteTerminalDisposition,
    pub usage: runne_provider::ProviderUsage,
    pub charge_micros: u64,
    pub currency: &'a str,
    pub settlement_digest: &'a [u8; 32],
}

impl ProviderRemoteTerminalDisposition {
    /// Stable versioned database code. Code four remains local cancellation uncertainty.
    pub const fn code(self) -> i64 {
        match self {
            Self::Completed => 1,
            Self::Failed => 2,
            Self::Incomplete => 3,
            Self::Cancelled => 5,
        }
    }
}

/// Encrypted normalized terminal response tied to one historical create attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteTerminalRecord {
    /// Immutable historical attempt and admission binding.
    pub binding: ProviderRemoteAttemptBinding,
    /// Journal encryption key identity.
    pub key: ProviderJournalKeyBinding,
    /// SHA-256 of the validated remote response ID.
    pub response_id_digest: [u8; 32],
    /// Factual provider terminal status.
    pub disposition: ProviderRemoteTerminalDisposition,
    /// Encrypted normalized remote terminal payload, including the response ID.
    pub encrypted_artifact: ProviderEncryptedPayload,
}

/// One consistent immutable view of request, response identity and factual outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRemoteAttemptRecord {
    /// Exact encrypted create parameters and historical binding.
    pub request: ProviderRemoteRequestIntent,
    /// Early remote response identity, when received.
    pub response: Option<ProviderRemoteIdentityRecord>,
    /// Factual remote terminal artifact, when observed.
    pub terminal: Option<ProviderRemoteTerminalRecord>,
}

/// Public projection material returned only after authenticated artifact reading.
/// It deliberately omits the provider response ID and encrypted journal details.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteAuthenticatedTerminalFact {
    status: runne_provider::ProviderRemoteResponseStatus,
    publication: runne_provider::ProviderRemotePublicationDisposition,
    output_digest: Option<[u8; 32]>,
}

impl ProviderRemoteAuthenticatedTerminalFact {
    /// Constructs the bounded, response-ID-free terminal projection.
    pub fn new(
        status: runne_provider::ProviderRemoteResponseStatus,
        publication: runne_provider::ProviderRemotePublicationDisposition,
        output_digest: Option<[u8; 32]>,
    ) -> Result<Self, runne_provider::ProviderRecoveryError> {
        let terminal = !matches!(
            &status,
            runne_provider::ProviderRemoteResponseStatus::Pending
                | runne_provider::ProviderRemoteResponseStatus::Unknown
        );
        if !terminal {
            return Err(runne_provider::ProviderRecoveryError::InvalidIdentity);
        }
        let allowed_completed = matches!(
            &status,
            runne_provider::ProviderRemoteResponseStatus::Completed { .. }
        ) && publication
            == runne_provider::ProviderRemotePublicationDisposition::Allowed;
        if allowed_completed != output_digest.is_some() {
            return Err(runne_provider::ProviderRecoveryError::InvalidIdentity);
        }
        Ok(Self {
            status,
            publication,
            output_digest,
        })
    }

    /// Authenticated bounded factual status and usage.
    pub const fn status(&self) -> &runne_provider::ProviderRemoteResponseStatus {
        &self.status
    }

    /// Local publication safety, kept separate from factual remote status.
    pub const fn publication_disposition(
        &self,
    ) -> runne_provider::ProviderRemotePublicationDisposition {
        self.publication
    }

    /// Authenticated SHA-256 of the exact publishable text; never contains text or remote ID.
    pub const fn output_digest(&self) -> Option<&[u8; 32]> {
        self.output_digest.as_ref()
    }
}

/// One transactionally consistent, credential-free provider projection for a
/// TaskRun effects read. The binding is historical identity; it never grants a
/// new dispatch or recovery operation.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteEffectsSnapshot {
    /// Exact immutable attempt selected by the TaskRun history.
    pub binding: ProviderRemoteAttemptBinding,
    /// Authenticated factual remote terminal, when one has been persisted.
    pub fact: Option<ProviderRemoteAuthenticatedTerminalFact>,
    /// Fresh nonterminal observation from the same database snapshot.
    pub observation: ProviderRemoteObservationProjection,
    /// Canonical local processing state for the authenticated fact.
    pub local_disposition: ProviderRemoteLocalDisposition,
    /// Actual accounting state, independent of remote status/publication.
    pub accounting: ProviderRemoteAccountingProjection,
    /// Durable secondary-grant state for the exact historical binding.
    pub secondary_grant: ProviderRemoteGrantProjection,
    /// Safe credential readiness read from the same database snapshot.
    pub credential: ProviderRemoteCredentialProjection,
    /// Successor eligibility proven from this exact database snapshot.
    pub successor_eligibility: runne_api::SuccessorEligibilityV1,
}

impl std::fmt::Debug for ProviderRemoteEffectsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRemoteEffectsSnapshot")
            .field("binding", &"[validated, redacted]")
            .field("terminal_fact_present", &self.fact.is_some())
            .field("observation", &self.observation)
            .field("local_disposition", &self.local_disposition)
            .field(
                "accounting_known",
                &matches!(
                    self.accounting,
                    ProviderRemoteAccountingProjection::Known { .. }
                ),
            )
            .field("secondary_grant", &self.secondary_grant)
            .field("credential", &self.credential)
            .field("successor_eligibility", &self.successor_eligibility)
            .finish()
    }
}

/// Safe projection of persisted nonterminal observation state.
/// It deliberately carries neither the observation time nor remote identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRemoteObservationProjection {
    NotObserved,
    Pending,
    Unknown,
}

/// Whether the saved factual response has been applied to local workflow state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRemoteLocalDisposition {
    Pending,
    OutputApplied,
    NoOutputApplied,
    AuditOnly,
    AcceptedCancellationClosed,
    /// Verified coding cancellation closure after all bound provider rounds are terminal.
    AcceptedCancellationAfterTerminal,
    Superseded,
    Unknown,
}

/// Financial certainty from the canonical settlement and original reservations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderRemoteAccountingProjection {
    NotApplicable,
    Unknown,
    Known {
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
        reasoning_output_tokens: u64,
        charge_micros: i64,
        currency: String,
    },
}

/// Durable authority state of the exact secondary profile grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRemoteGrantProjection {
    NotSecondary,
    Active { authority_revision: u64 },
    Revoked { authority_revision: u64 },
    MissingOrMismatch,
}

/// Safe credential state, without a provider secret or credential reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRemoteCredentialProjection {
    NotConfigured,
    Ready,
    Missing,
    Stale,
    Unavailable,
    Unsupported,
    AccessDenied,
    Conflict,
    InvariantFailure,
}

impl ProviderRemoteTerminalRecord {
    /// Constructs a bounded artifact after provider-specific validation and encryption.
    pub fn new(
        binding: ProviderRemoteAttemptBinding,
        key: ProviderJournalKeyBinding,
        response_id_digest: [u8; 32],
        disposition: ProviderRemoteTerminalDisposition,
        encrypted_artifact: ProviderEncryptedPayload,
    ) -> Result<Self, ProviderExecutionError> {
        if response_id_digest == [0; 32]
            || encrypted_artifact.plaintext_len() == 0
            || encrypted_artifact.plaintext_len() > 131_072
            || encrypted_artifact.ciphertext().len() > 131_088
        {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        Ok(Self {
            binding,
            key,
            response_id_digest,
            disposition,
            encrypted_artifact,
        })
    }
}

impl fmt::Debug for ProviderRemoteTerminalRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRemoteTerminalRecord")
            .field("provider_attempt_id", &self.binding.dispatch_attempt_id)
            .field("disposition", &self.disposition)
            .field("response_id_digest", &"[redacted]")
            .field("encrypted_artifact", &self.encrypted_artifact)
            .finish()
    }
}
