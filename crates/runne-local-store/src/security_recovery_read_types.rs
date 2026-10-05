use crate::{
    ClientMutationDisposition, MutationOperation, MutationTargetKind, SecurityStateError,
    StoredMutationTarget,
};

pub const MAX_MUTATION_RECOVERY_RECORDS: usize = 64;

/// Complete durable runtime identity digest and principal digest for recovery reads.
///
/// Callers must provide the complete durable runtime identity digest established
/// at admission; an authority-only digest is not a substitute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationRecoveryBinding {
    pub(crate) runtime_identity_digest: [u8; 32],
    pub(crate) principal_digest: [u8; 32],
}

impl MutationRecoveryBinding {
    /// # Errors
    ///
    /// Returns an error for an absent durable identity binding.
    pub fn new(
        runtime_identity_digest: [u8; 32],
        principal_digest: [u8; 32],
    ) -> Result<Self, SecurityStateError> {
        (runtime_identity_digest != [0; 32] && principal_digest != [0; 32])
            .then_some(Self {
                runtime_identity_digest,
                principal_digest,
            })
            .ok_or(SecurityStateError::InvalidIdentity)
    }
}

/// Bounded page size for restart recovery reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationRecoveryLimit(pub(crate) usize);

impl MutationRecoveryLimit {
    /// # Errors
    ///
    /// Returns an error when the requested page is empty or exceeds the hard cap.
    pub fn new(value: usize) -> Result<Self, SecurityStateError> {
        (value != 0 && value <= MAX_MUTATION_RECOVERY_RECORDS)
            .then_some(Self(value))
            .ok_or(SecurityStateError::InvalidTransition)
    }
}

/// Immutable, non-secret evidence for one resumable v7 mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationRecoveryEvidence {
    pub(crate) operation: MutationOperation,
    pub(crate) target: StoredMutationTarget,
    pub(crate) idempotency_key: String,
    pub(crate) expected_version: u64,
    pub(crate) semantic_digest: [u8; 32],
    pub(crate) normalized_command: crate::NormalizedMutationCommand,
    pub(crate) disposition: ClientMutationDisposition,
    pub(crate) resend_count: u8,
}

impl MutationRecoveryEvidence {
    #[must_use]
    pub const fn operation(&self) -> MutationOperation {
        self.operation
    }
    #[must_use]
    pub const fn target(&self) -> &StoredMutationTarget {
        &self.target
    }
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    #[must_use]
    pub const fn expected_version(&self) -> u64 {
        self.expected_version
    }
    #[must_use]
    pub const fn semantic_digest(&self) -> [u8; 32] {
        self.semantic_digest
    }
    #[must_use]
    pub const fn normalized_command(&self) -> &crate::NormalizedMutationCommand {
        &self.normalized_command
    }
    #[must_use]
    pub const fn disposition(&self) -> ClientMutationDisposition {
        self.disposition
    }
    #[must_use]
    pub const fn resend_count(&self) -> u8 {
        self.resend_count
    }
}

/// One bounded, deterministic recovery page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationRecoveryBatch {
    pub(crate) records: Vec<MutationRecoveryEvidence>,
    pub(crate) has_more: bool,
}

/// Authenticated native-only view of one exact v7 mutation ledger row.
///
/// This intentionally has no serialization implementation: normalized commands
/// can contain prompts and are for native recovery only.
#[derive(Clone, Eq, PartialEq)]
pub struct MutationReceiptV7 {
    pub(crate) runtime_identity_digest: [u8; 32],
    pub(crate) principal_digest: [u8; 32],
    pub(crate) record: crate::MutationRecord,
}

impl std::fmt::Debug for MutationReceiptV7 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MutationReceiptV7(<native-only, redacted>)")
    }
}

impl MutationReceiptV7 {
    #[must_use]
    pub const fn runtime_identity_digest(&self) -> [u8; 32] {
        self.runtime_identity_digest
    }
    #[must_use]
    pub const fn principal_digest(&self) -> [u8; 32] {
        self.principal_digest
    }
    #[must_use]
    pub const fn record(&self) -> &crate::MutationRecord {
        &self.record
    }
}

impl MutationRecoveryBatch {
    #[must_use]
    pub fn records(&self) -> &[MutationRecoveryEvidence] {
        &self.records
    }
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

pub fn operation_from_name(value: &str) -> Result<MutationOperation, SecurityStateError> {
    match value {
        "project_rename" => Ok(MutationOperation::ProjectRename),
        "project_create" => Ok(MutationOperation::ProjectCreate),
        "project_archive" => Ok(MutationOperation::ProjectArchive),
        "project_delete" => Ok(MutationOperation::ProjectDelete),
        "workspace_create" => Ok(MutationOperation::WorkspaceCreate),
        "workspace_bind_root" => Ok(MutationOperation::WorkspaceBindRoot),
        "workspace_open" => Ok(MutationOperation::WorkspaceOpen),
        "conversation_create" => Ok(MutationOperation::ConversationCreate),
        "conversation_generate_text" => Ok(MutationOperation::ConversationGenerateText),
        "task_run_submit" => Ok(MutationOperation::TaskRunSubmit),
        "task_run_cancel" => Ok(MutationOperation::TaskRunCancel),
        "task_run_unknown_successor" => Ok(MutationOperation::TaskRunUnknownSuccessor),
        "approval_respond" => Ok(MutationOperation::ApprovalRespond),
        "device_revoke" => Ok(MutationOperation::DeviceRevoke),
        "runtime_stop" => Ok(MutationOperation::RuntimeStop),
        "update_install" => Ok(MutationOperation::UpdateInstall),
        "domain_reset" => Ok(MutationOperation::DomainReset),
        _ => Err(SecurityStateError::IdentityConflict),
    }
}

pub fn target_from_name(value: &str) -> Result<MutationTargetKind, SecurityStateError> {
    match value {
        "project" => Ok(MutationTargetKind::Project),
        "workspace" => Ok(MutationTargetKind::Workspace),
        "conversation" => Ok(MutationTargetKind::Conversation),
        "task_run" => Ok(MutationTargetKind::TaskRun),
        "approval" => Ok(MutationTargetKind::Approval),
        "device" => Ok(MutationTargetKind::Device),
        "runtime" => Ok(MutationTargetKind::Runtime),
        "update" => Ok(MutationTargetKind::Update),
        "domain" => Ok(MutationTargetKind::Domain),
        _ => Err(SecurityStateError::IdentityConflict),
    }
}
