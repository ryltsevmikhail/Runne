/// Closed source settlement result returned after an authenticated artifact is
/// joined to the original TaskRun generation inside one store transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRemoteTerminalSourceOutcome {
    /// The current generation and writer fence still permit local application.
    CurrentGeneration,
    /// The remote fact is retained for audit; this generation cannot receive it.
    AuditOnly,
}

/// Opaque source fact request constructed only after runtime artifact
/// authentication and optional exact historical pricing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRemoteTerminalSourceCommit {
    attempt_id: DispatchAttemptId,
    taskrun_id: runne_domain::id::TaskRunId,
    taskrun_attempt_id: runne_domain::id::AttemptId,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    runtime_generation: u64,
    fencing_token: u64,
    request_digest: [u8; 32],
    response_id_digest: [u8; 32],
    artifact_digest: [u8; 32],
    output_digest: Option<[u8; 32]>,
    profile_digest: [u8; 32],
    pricing_revision_digest: [u8; 32],
    terminal_status: ProviderRemoteTerminalDisposition,
    publication_disposition: runne_provider::ProviderRemotePublicationDisposition,
    usage: Option<ProviderUsage>,
    charge_micros: Option<u64>,
    currency: Option<String>,
    settlement_digest: Option<[u8; 32]>,
}

impl ProviderRemoteTerminalSourceCommit {
    /// Constructs one opaque source commit request for the runtime persistence port.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authenticated_terminal(
        attempt_id: DispatchAttemptId,
        taskrun_id: runne_domain::id::TaskRunId,
        taskrun_attempt_id: runne_domain::id::AttemptId,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        runtime_generation: u64,
        fencing_token: u64,
        request_digest: [u8; 32],
        response_id_digest: [u8; 32],
        artifact_digest: [u8; 32],
        output_digest: Option<[u8; 32]>,
        profile_digest: [u8; 32],
        pricing_revision_digest: [u8; 32],
        terminal_status: ProviderRemoteTerminalDisposition,
        publication_disposition: runne_provider::ProviderRemotePublicationDisposition,
        usage: Option<ProviderUsage>,
        charge_micros: Option<u64>,
        currency: Option<String>,
        settlement_digest: Option<[u8; 32]>,
    ) -> Result<Self, ProviderExecutionError> {
        let any_price =
            charge_micros.is_some() || currency.is_some() || settlement_digest.is_some();
        let complete_price =
            charge_micros.is_some() && currency.is_some() && settlement_digest.is_some();
        let publishable_completed = terminal_status == ProviderRemoteTerminalDisposition::Completed
            && publication_disposition
                == runne_provider::ProviderRemotePublicationDisposition::Allowed;
        if runtime_authority_id == [0; 16]
            || database_generation == 0
            || runtime_generation == 0
            || fencing_token == 0
            || request_digest == [0; 32]
            || response_id_digest == [0; 32]
            || artifact_digest == [0; 32]
            || output_digest == Some([0; 32])
            || profile_digest == [0; 32]
            || pricing_revision_digest == [0; 32]
            || any_price != complete_price
            || (complete_price && usage.is_none())
            || publishable_completed != output_digest.is_some()
            || (complete_price && currency.as_ref().is_none_or(|value| value.len() != 3))
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        Ok(Self {
            attempt_id,
            taskrun_id,
            taskrun_attempt_id,
            runtime_authority_id,
            database_generation,
            runtime_generation,
            fencing_token,
            request_digest,
            response_id_digest,
            artifact_digest,
            output_digest,
            profile_digest,
            pricing_revision_digest,
            terminal_status,
            publication_disposition,
            usage,
            charge_micros,
            currency,
            settlement_digest,
        })
    }

    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.attempt_id
    }
    pub const fn taskrun_id(&self) -> runne_domain::id::TaskRunId {
        self.taskrun_id
    }
    pub const fn taskrun_attempt_id(&self) -> runne_domain::id::AttemptId {
        self.taskrun_attempt_id
    }
    pub const fn runtime_authority_id(&self) -> &[u8; 16] {
        &self.runtime_authority_id
    }
    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub const fn response_id_digest(&self) -> &[u8; 32] {
        &self.response_id_digest
    }
    pub const fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }
    pub const fn output_digest(&self) -> Option<&[u8; 32]> {
        self.output_digest.as_ref()
    }
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }
    pub const fn pricing_revision_digest(&self) -> &[u8; 32] {
        &self.pricing_revision_digest
    }
    pub const fn terminal_status(&self) -> ProviderRemoteTerminalDisposition {
        self.terminal_status
    }
    pub const fn publication_disposition(
        &self,
    ) -> runne_provider::ProviderRemotePublicationDisposition {
        self.publication_disposition
    }
    pub const fn usage(&self) -> Option<ProviderUsage> {
        self.usage
    }
    pub const fn charge_micros(&self) -> Option<u64> {
        self.charge_micros
    }
    pub fn currency(&self) -> Option<&str> {
        self.currency.as_deref()
    }
    pub const fn settlement_digest(&self) -> Option<&[u8; 32]> {
        self.settlement_digest.as_ref()
    }
}
