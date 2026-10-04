/// Immutable provider identity captured before a remote create request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRemoteAttemptBinding {
    /// TaskRun and local attempt identities.
    pub taskrun_id: TaskRunId,
    /// Local execution attempt.
    pub taskrun_attempt_id: AttemptId,
    /// Provider dispatch attempt.
    pub dispatch_attempt_id: DispatchAttemptId,
    /// Exact provider and credential account realm.
    pub provider_id: String,
    /// Distinct lifecycle credential realm.
    pub credential_realm: String,
    /// Versioned profile identifier and digest.
    pub profile_id: String,
    /// Profile digest.
    pub profile_digest: [u8; 32],
    /// Pricing revision digest.
    pub pricing_digest: [u8; 32],
    /// Canonical semantic request digest.
    pub semantic_digest: [u8; 32],
    /// Prepared request digest.
    pub prepared_digest: [u8; 32],
    /// Exact rendered request digest.
    pub request_digest: [u8; 32],
    /// Runtime authority/database identity.
    pub runtime_authority_id: [u8; 16],
    /// Database generation.
    pub database_generation: u64,
    /// Runtime generation and fence.
    pub runtime_generation: u64,
    /// Effect-start fencing token.
    pub fencing_token: u64,
}

/// Credential-free exact rendered create payload sealed by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRemoteRequestIntent {
    /// Immutable attempt and admission binding.
    pub binding: ProviderRemoteAttemptBinding,
    /// Journal encryption key identity.
    pub key: ProviderJournalKeyBinding,
    /// Encrypted bounded request bytes.
    pub encrypted_request: ProviderEncryptedPayload,
}

/// Encrypted provider response identity committed before stream exposure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRemoteIdentityRecord {
    /// Immutable attempt and admission binding.
    pub binding: ProviderRemoteAttemptBinding,
    /// Journal encryption key identity.
    pub key: ProviderJournalKeyBinding,
    /// Encrypted response ID bytes.
    pub encrypted_response_id: ProviderEncryptedPayload,
}

/// Bounded keyset page of attempts with a durably saved provider response ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRemoteAttemptPage {
    /// Sorted unique persisted dispatch attempt identifiers.
    pub attempts: Vec<DispatchAttemptId>,
    /// Last examined attempt, for the next keyset request.
    pub next_after: Option<DispatchAttemptId>,
    /// True when fewer than the requested number of attempts were returned.
    pub reached_end: bool,
}

/// Append-only persistence port for remote request and response identities.
pub trait ProviderRemoteRecoveryStore: Send + Sync {
    /// Finds at most one unresolved saved-ID attempt for an exact TaskRun assignment.
    fn find_remote_attempt(
        &self,
        _taskrun_id: TaskRunId,
        _taskrun_attempt_id: AttemptId,
    ) -> Result<Option<DispatchAttemptId>, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }
    /// Finds the immutable historical provider attempt for an exact assignment,
    /// including artifacts already acknowledged or otherwise settled.
    fn find_remote_attempt_history(
        &self,
        _taskrun_id: TaskRunId,
        _taskrun_attempt_id: AttemptId,
    ) -> Result<Option<DispatchAttemptId>, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }
    /// Loads the unique historical attempt and encrypted facts from one DB snapshot.
    fn load_remote_attempt_history(
        &self,
        _taskrun_id: TaskRunId,
        _taskrun_attempt_id: AttemptId,
    ) -> Result<Option<ProviderRemoteAttemptRecord>, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }
    /// Returns the admitted digest contract for an exact persisted remote attempt.
    fn load_remote_call_digest_version(
        &self,
        _attempt: DispatchAttemptId,
    ) -> Result<runne_provider::ProviderCallDigestVersion, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }
    /// Scans bounded persisted attempts with a durable response ID.
    fn scan_remote_attempts(
        &self,
        _after: Option<DispatchAttemptId>,
        _limit: usize,
    ) -> Result<ProviderRemoteAttemptPage, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }
    /// Resolves a full immutable attempt binding from a current admitted dispatch.
    fn resolve_remote_attempt_binding(
        &self,
        _claim: &runne_provider::ProviderDispatchClaim,
        _provider_id: &runne_provider::ProviderId,
        _credential_realm: &runne_provider::ProviderId,
        _profile_id: &str,
    ) -> Result<ProviderRemoteAttemptBinding, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

    /// Checks whether this exact saved attempt has a verified accepted cancel fence.
    fn remote_cancel_requested(
        &self,
        _binding: &ProviderRemoteAttemptBinding,
    ) -> Result<bool, ProviderExecutionError> {
        Ok(false)
    }

    /// Reserves a persisted one-use proof for a fresh same-response operation.
    fn issue_remote_operation_proof(
        &self,
        _binding: &ProviderRemoteAttemptBinding,
        _response_id: &runne_provider::RemoteResponseId,
        _operation: runne_provider::ProviderRecoveryOperation,
    ) -> Result<runne_provider::ProviderRemoteOperationProof, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

    /// Revalidates the persisted issued row and current owner before native use.
    fn validate_remote_operation_proof(
        &self,
        _proof: &ProviderRemoteOperationProof,
        _response_id: &runne_provider::RemoteResponseId,
    ) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

    /// Persists the exact credential-free request before any network send.
    fn persist_remote_request(
        &self,
        request: &ProviderRemoteRequestIntent,
    ) -> Result<(), ProviderExecutionError>;

    /// Commits the first validated response ID before later stream events.
    fn commit_remote_response_id(
        &self,
        response: &ProviderRemoteIdentityRecord,
    ) -> Result<(), ProviderExecutionError>;

    /// Loads encrypted request/identity records for bounded recovery.
    fn load_remote_identity(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<
        Option<(
            ProviderRemoteRequestIntent,
            Option<ProviderRemoteIdentityRecord>,
        )>,
        ProviderExecutionError,
    >;

    /// Atomically persists validated terminal evidence under the historical attempt binding.
    fn commit_remote_terminal_artifact(
        &self,
        _artifact: &ProviderRemoteTerminalRecord,
    ) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

    /// Atomically consumes a fresh status/cancel operation proof with the factual artifact.
    fn commit_remote_terminal_artifact_with_proof(
        &self,
        _artifact: &ProviderRemoteTerminalRecord,
        _proof: &ProviderRemoteOperationProof,
    ) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

    /// Consumes a proof after a pending/unknown observation without changing terminal facts.
    fn commit_remote_operation_observation(
        &self,
        _proof: &ProviderRemoteOperationProof,
        _status: runne_provider::ProviderRemoteResponseStatus,
    ) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

    /// Loads the immutable terminal artifact for exact local reconciliation.
    fn load_remote_terminal_artifact(
        &self,
        _attempt: DispatchAttemptId,
    ) -> Result<Option<ProviderRemoteTerminalRecord>, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

    /// Loads all immutable remote facts from one consistent database snapshot.
    fn load_remote_attempt(
        &self,
        _attempt: DispatchAttemptId,
    ) -> Result<Option<ProviderRemoteAttemptRecord>, ProviderExecutionError> {
        // Sequential trait calls cannot promise one consistent database view.
        // Implementations must override this with a single-snapshot read.
        Err(ProviderExecutionError::StoreUnavailable)
    }
}

/// Trusted boundary for projecting encrypted remote facts inside a caller's
/// consistent database snapshot. Implementations authenticate request, ID,
/// artifact AEAD/AAD, and exact historical profile identity before returning.
pub trait ProviderRemoteFactAuthenticator: Send + Sync {
    /// Returns one bounded factual artifact, or `None` when no terminal fact exists.
    fn authenticate_terminal_snapshot(
        &self,
        snapshot: &ProviderRemoteAttemptRecord,
        expected: &runne_provider::ProviderRecoveryAttemptIdentity,
    ) -> Result<
        Option<ProviderRemoteAuthenticatedTerminalFact>,
        runne_provider::ProviderRecoveryError,
    >;

    /// Recomputes the canonical terminal settlement digest using the
    /// authenticated response ID held only inside this trusted boundary.
    /// Implementations without that ability fail closed by returning `false`.
    fn verify_terminal_settlement_digest(
        &self,
        _snapshot: &ProviderRemoteAttemptRecord,
        _expected: &runne_provider::ProviderRecoveryAttemptIdentity,
        _candidate: ProviderRemoteTerminalSettlementDigestCandidate<'_>,
    ) -> Result<bool, runne_provider::ProviderRecoveryError> {
        Ok(false)
    }
}
