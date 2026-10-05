use runne_application::ports::TaskRunAssignmentIdentity;
use runne_application::provider::{ProviderEncryptedPayload, ProviderJournalKeyBinding};
use runne_domain::id::{AttemptId, CycleId, IntegrityDigest, TaskRunId};

pub const MAX_TOOL_ARGUMENT_BYTES: usize = 8 * 1024;
pub const MAX_TOOL_RESULT_BYTES: usize = 8 * 1024;
pub const MAX_HELPER_RECEIPT_BYTES: usize = 16 * 1024;
pub const MAX_TOOL_EFFECTS: u32 = 2;
pub const MAX_CONTINUATIONS: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ToolInvocationKey {
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub cycle_id: CycleId,
    pub proposal_index: u32,
}

impl ToolInvocationKey {
    /// Deterministic opaque nonce for one invocation's managed execution area.
    /// The UUID bits are an encoding convention only; this value is not a timestamp.
    pub fn managed_area_nonce(&self, semantic_digest: IntegrityDigest) -> [u8; 16] {
        use sha2::{Digest, Sha256};
        let mut bytes: [u8; 16] = Sha256::new()
            .chain_update(b"RUNNE_D2_TOOL_AREA_BINDING_V1\0")
            .chain_update(self.taskrun_id.as_bytes())
            .chain_update(self.attempt_id.as_bytes())
            .chain_update(self.cycle_id.as_bytes())
            .chain_update(self.proposal_index.to_be_bytes())
            .chain_update(semantic_digest.as_bytes())
            .finalize()[..16]
            .try_into()
            .expect("fixed digest prefix");
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSourceRef {
    pub dispatch_attempt_id: [u8; 16],
    pub sequence: u64,
    pub event_kind: u8,
    pub terminal: bool,
    pub plaintext_digest: IntegrityDigest,
    pub profile_digest: IntegrityDigest,
    pub runtime_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocationBindingV1 {
    pub key: ToolInvocationKey,
    pub expected_taskrun_version: u64,
    pub call_id: String,
    pub tool_name: String,
    pub tool_revision: String,
    pub schema_digest: IntegrityDigest,
    pub canonical_arguments: Vec<u8>,
    pub arguments_digest: IntegrityDigest,
    pub semantic_digest: IntegrityDigest,
    pub sources: Vec<ToolSourceRef>,
    pub environment_id: String,
    pub environment_revision: String,
    pub root_identity: IntegrityDigest,
    pub root_revision: u64,
    pub target_name: String,
    pub target_precondition: Option<IntegrityDigest>,
    pub approval_id: [u8; 16],
    pub principal_id: String,
    pub approval_principal_id: String,
    pub approval_action: String,
    pub approval_resource: String,
    pub approval_digest: IntegrityDigest,
    pub policy_revision: u64,
    pub approval_expires_at: i64,
    pub round_index: u32,
}

/// Encrypted canonical tool content produced by the runtime journal key boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedToolPayloadV1 {
    pub key: ProviderJournalKeyBinding,
    pub payload: ProviderEncryptedPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolInvocationState {
    Proposed,
    Approved,
    Denied,
    Claimed,
    Uncertain,
    Result,
    Cancelled,
    AuditOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocationResult {
    /// Plaintext is always empty in store records; open `receipt_payload` in runtime.
    pub bytes: Vec<u8>,
    pub digest: IntegrityDigest,
    pub actual_length: u64,
    pub truncated: bool,
    pub receipt_payload: EncryptedToolPayloadV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolInvocationBudget {
    pub effects_used: u32,
    pub continuations_used: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocationReceipt {
    pub key: ToolInvocationKey,
    pub state: ToolInvocationState,
    pub semantic_digest: IntegrityDigest,
    pub result: Option<ToolInvocationResult>,
    pub budget: ToolInvocationBudget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocationStoredRecord {
    pub binding: ToolInvocationBindingV1,
    pub arguments_payload: EncryptedToolPayloadV1,
    pub receipt: ToolInvocationReceipt,
    pub updated_at: i64,
    pub release_started: bool,
    pub continuation_started: bool,
    pub claim_assignment: Option<TaskRunAssignmentIdentity>,
    pub managed_area_identity: Option<[u8; 100]>,
    pub local_stop_state: LocalToolStopState,
    pub empty_proof_identity: Option<[u8; 100]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalToolStopState {
    NotLaunched,
    Launched,
    ProvedEmpty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolApprovalBindingV1 {
    pub key: ToolInvocationKey,
    pub approval_id: [u8; 16],
    pub decision_principal_id: String,
    pub expected_policy_revision: u64,
    pub expected_action_digest: IntegrityDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedToolReceiptV1 {
    pub key: ToolInvocationKey,
    pub semantic_digest: IntegrityDigest,
    pub receipt_payload: EncryptedToolPayloadV1,
    pub result_digest: IntegrityDigest,
    pub actual_length: u64,
    pub truncated: bool,
    pub assignment: TaskRunAssignmentIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolInvocationStoreError {
    Conflict,
    ProposalConflict(ProposalConflictKind),
    StaleVersion,
    InvalidState,
    ApprovalDenied,
    ApprovalExpired,
    BudgetExhausted,
    Cancelled,
    Uncertain,
    CorruptData,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalConflictKind {
    Binding,
    Sources,
    DuplicateEffect,
    EffectDigestToolMismatch,
    EffectDigestArgumentsMismatch,
    EffectDigestTargetMismatch,
    EffectDigestRootMismatch,
    PayloadNonce,
    InsertUnique,
    InsertCheck,
    InsertForeignKey,
    InsertOther,
}
