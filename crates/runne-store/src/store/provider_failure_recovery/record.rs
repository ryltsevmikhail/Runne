use super::*;

/// One locally settled remote-failure attempt still attached to a running text TaskRun.
#[derive(Clone)]
pub struct ProviderFailureRecoveryRecord {
    /// Kind of durable terminal evidence associated with this candidate.
    pub kind: ProviderFailureRecoveryKind,
    /// Stable provider pre-effect rejection reason code, when applicable.
    pub pre_effect_rejection: Option<i64>,
    /// Provider dispatch attempt whose authenticated journal must be rechecked.
    pub dispatch_attempt_id: [u8; 16],
    /// Exact TaskRun and runtime attempt bound to the provider admission.
    pub taskrun_id: TaskRunId,
    /// Conversation admitted by the provider effect.
    pub conversation_id: ConversationId,
    /// Runtime attempt persisted in the TaskRun provider admission.
    pub execution_attempt_id: AttemptId,
    /// Assignment fence which must be retired by finish_text.
    pub assignment: TaskRunAssignmentIdentity,
    /// TaskRun version at canonical text start.
    pub claim_version: u64,
    /// Authenticated submitting principal bound to provider admission.
    pub principal_id: String,
    /// Immutable exact prompt from the submitted TaskRun event.
    pub submitted_prompt: String,
    /// Workspace from the immutable TaskRun submission.
    pub workspace_id: Option<WorkspaceId>,
    /// Original actor from the immutable TaskRun submission.
    pub submit_actor: Option<Actor>,
    /// Provider generation used to bind the terminal settlement.
    pub runtime_generation: u64,
    /// Provider attempt fencing token included in the settlement digest.
    pub provider_fencing_token: u64,
    /// Exact provider profile digest.
    pub profile_digest: [u8; 32],
    /// Exact pricing revision digest.
    pub pricing_revision_digest: [u8; 32],
    /// Accounting settlement digest to recompute from the journal.
    pub settlement_digest: [u8; 32],
    /// Persisted terminal accounting values.
    pub input_tokens: u64,
    /// Persisted terminal accounting values.
    pub output_tokens: u64,
    /// Persisted terminal accounting values.
    pub cached_input_tokens: u64,
    /// Persisted terminal accounting values.
    pub reasoning_output_tokens: u64,
    /// Persisted terminal accounting values.
    pub charge_micros: u64,
    /// Persisted accounting currency.
    pub currency: String,
    /// Current exact cancellation successor version, when cancellation won.
    pub cancellation_taskrun_version: Option<u64>,
    /// Immutable v50 disposition marker; historical rows are intentionally absent.
    pub terminal_disposition: Option<ProviderTerminalDisposition>,
}

/// Durable provider outcome accepted by TaskRun failure recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailureRecoveryKind {
    /// Provider terminal failure was locally settled with accounting evidence.
    SettledRemoteFailure,
    /// Coordinator durably rejected before starting the provider effect.
    RejectedBeforeEffect,
}

/// One authenticated Source1 terminal whose finance remains Unknown.
#[derive(Clone)]
pub struct ProviderUnknownFailureRecoveryRecord {
    /// Internal dispatch identity used only to authenticate the local journal.
    pub dispatch_attempt_id: [u8; 16],
    /// Canonical TaskRun, Conversation, and runtime attempt identities.
    pub taskrun_id: TaskRunId,
    pub conversation_id: ConversationId,
    pub execution_attempt_id: AttemptId,
    /// Original claim identity and Started version.
    pub assignment: TaskRunAssignmentIdentity,
    pub claim_version: u64,
    /// Submitter identity validated against the immutable submit origin.
    pub principal_id: String,
    pub submitted_prompt: String,
    pub workspace_id: Option<WorkspaceId>,
    pub submit_actor: Option<Actor>,
    /// Journal AAD and source pins needed for runtime replay authentication.
    pub fencing_token: u64,
    pub runtime_generation: u64,
    pub profile_digest: [u8; 32],
    pub call_digest_version: runne_provider::ProviderCallDigestVersion,
    pub terminal_sequence: u64,
    pub disposition: ProviderTerminalDisposition,
    /// Exact usage when present; absent usage stays absent.
    pub usage: Option<runne_provider::ProviderUsage>,
    /// Opaque Unknown commitment, never a financial settlement digest.
    pub unknown_commitment: [u8; 32],
    /// Pending cancellation successor, if cancellation won before recovery.
    pub cancellation_taskrun_version: Option<u64>,
}

impl std::fmt::Debug for ProviderUnknownFailureRecoveryRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderUnknownFailureRecoveryRecord")
            .field("dispatch_attempt_id", &self.dispatch_attempt_id)
            .field("taskrun_id", &self.taskrun_id)
            .field("conversation_id", &self.conversation_id)
            .field("execution_attempt_id", &self.execution_attempt_id)
            .field("submitted_prompt", &"[redacted]")
            .field("unknown_commitment", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// A bounded page of immutable Unknown failure candidates.
#[derive(Debug, Clone)]
pub struct ProviderUnknownFailureRecoveryPage {
    /// Candidates with exact original TaskRun/Conversation submission lineage.
    pub candidates: Vec<ProviderUnknownFailureRecoveryRecord>,
    /// Last dispatch identity examined.
    pub next_cursor: Option<[u8; 16]>,
    /// Whether the query reached its end.
    pub reached_end: bool,
}

impl std::fmt::Debug for ProviderFailureRecoveryRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderFailureRecoveryRecord")
            .field("dispatch_attempt_id", &self.dispatch_attempt_id)
            .field("taskrun_id", &self.taskrun_id)
            .field("conversation_id", &self.conversation_id)
            .field("execution_attempt_id", &self.execution_attempt_id)
            .field("submitted_prompt", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// One bounded scan page, including the cursor after all examined rows.
#[derive(Debug, Clone)]
pub struct ProviderFailureRecoveryPage {
    /// Candidates with validated submitted TaskRun lineage.
    pub candidates: Vec<ProviderFailureRecoveryRecord>,
    /// Last provider attempt ID examined, even when its lineage was invalid.
    pub next_cursor: Option<[u8; 16]>,
    /// Whether the query returned fewer rows than the requested page size.
    pub reached_end: bool,
}
