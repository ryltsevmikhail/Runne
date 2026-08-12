use gocode_domain::id::IdempotencyKey;
use gocode_secure_store::SecurityAnchorV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOperation {
    ProjectCreate, ProjectArchive, ProjectDelete, WorkspaceCreate, WorkspaceBindRoot,
    WorkspaceOpen, ConversationCreate, ConversationGenerateText, TaskRunCancel,
    ApprovalRespond, DeviceRevoke, RuntimeStop, UpdateInstall, DomainReset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationTargetKind {
    Project, Workspace, Conversation, TaskRun, Approval, Runtime, Device, Update, Domain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedCanonicalId(Vec<u8>);

#[allow(clippy::missing_errors_doc)]
impl BoundedCanonicalId {
    pub fn parse(value: &[u8]) -> Result<Self, SecurityStateError> {
        if value.is_empty() || value.len() > 128 || !value.iter().all(u8::is_ascii_graphic) {
            return Err(SecurityStateError::InvalidIdentity);
        }
        Ok(Self(value.to_vec()))
    }

    pub(crate) fn bytes(&self) -> &[u8] { &self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredMutationTarget { kind: MutationTargetKind, canonical_id: BoundedCanonicalId }

#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl StoredMutationTarget {
    pub fn new(kind: MutationTargetKind, canonical_id: BoundedCanonicalId) -> Self {
        Self { kind, canonical_id }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationIdentity {
    runtime_authority_digest: [u8; 32], principal_digest: [u8; 32], operation: MutationOperation,
    target: StoredMutationTarget, idempotency_key: IdempotencyKey, expected_version: u64,
    semantic_digest: [u8; 32],
}

#[allow(clippy::missing_errors_doc, clippy::missing_const_for_fn)]
impl MutationIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime_authority_digest: [u8; 32], principal_digest: [u8; 32], operation: MutationOperation,
        target_kind: MutationTargetKind, canonical_id: BoundedCanonicalId, idempotency_key: impl Into<String>,
        expected_version: u64, semantic_digest: [u8; 32],
    ) -> Result<Self, SecurityStateError> {
        if !operation_accepts(operation, target_kind) || runtime_authority_digest == [0; 32]
            || principal_digest == [0; 32] || semantic_digest == [0; 32] {
            return Err(SecurityStateError::InvalidIdentity);
        }
        let idempotency_key = IdempotencyKey::new(idempotency_key.into())
            .map_err(|_| SecurityStateError::InvalidIdentity)?;
        Ok(Self { runtime_authority_digest, principal_digest, operation,
            target: StoredMutationTarget::new(target_kind, canonical_id), idempotency_key,
            expected_version, semantic_digest })
    }

    pub(crate) fn semantic_digest(&self) -> [u8; 32] { self.semantic_digest }
    pub(crate) fn idempotency_key(&self) -> &str { self.idempotency_key.as_str() }
    pub(crate) fn runtime(&self) -> [u8; 32] { self.runtime_authority_digest }
    pub(crate) fn principal(&self) -> [u8; 32] { self.principal_digest }
    pub(crate) fn expected_version(&self) -> u64 { self.expected_version }
    pub(crate) fn target(&self) -> &[u8] { self.target.canonical_id.bytes() }
    pub(crate) fn operation_name(&self) -> &'static str { match self.operation { MutationOperation::ProjectCreate => "project_create", MutationOperation::ProjectArchive => "project_archive", MutationOperation::ProjectDelete => "project_delete", MutationOperation::WorkspaceCreate => "workspace_create", MutationOperation::WorkspaceBindRoot => "workspace_bind_root", MutationOperation::WorkspaceOpen => "workspace_open", MutationOperation::ConversationCreate => "conversation_create", MutationOperation::ConversationGenerateText => "conversation_generate_text", MutationOperation::TaskRunCancel => "task_run_cancel", MutationOperation::ApprovalRespond => "approval_respond", MutationOperation::DeviceRevoke => "device_revoke", MutationOperation::RuntimeStop => "runtime_stop", MutationOperation::UpdateInstall => "update_install", MutationOperation::DomainReset => "domain_reset" } }
    pub(crate) fn target_name(&self) -> &'static str { match self.target.kind { MutationTargetKind::Project => "project", MutationTargetKind::Workspace => "workspace", MutationTargetKind::Conversation => "conversation", MutationTargetKind::TaskRun => "task_run", MutationTargetKind::Approval => "approval", MutationTargetKind::Runtime => "runtime", MutationTargetKind::Device => "device", MutationTargetKind::Update => "update", MutationTargetKind::Domain => "domain" } }
}

const fn operation_accepts(operation: MutationOperation, target: MutationTargetKind) -> bool {
    matches!((operation, target),
        (MutationOperation::ProjectCreate | MutationOperation::ProjectArchive | MutationOperation::ProjectDelete, MutationTargetKind::Project)
        | (MutationOperation::WorkspaceCreate | MutationOperation::WorkspaceBindRoot | MutationOperation::WorkspaceOpen, MutationTargetKind::Workspace)
        | (MutationOperation::ConversationCreate | MutationOperation::ConversationGenerateText, MutationTargetKind::Conversation)
        | (MutationOperation::TaskRunCancel, MutationTargetKind::TaskRun)
        | (MutationOperation::ApprovalRespond, MutationTargetKind::Approval)
        | (MutationOperation::DeviceRevoke, MutationTargetKind::Device)
        | (MutationOperation::RuntimeStop, MutationTargetKind::Runtime)
        | (MutationOperation::UpdateInstall, MutationTargetKind::Update)
        | (MutationOperation::DomainReset, MutationTargetKind::Domain))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientMutationDisposition { Prepared, Dispatching, Observing, CanonicalOutcome, Retryable, Reconciling, ManualResolution }
impl ClientMutationDisposition { pub(crate) const fn transition_to(self, next: Self) -> bool { matches!((self, next), (Self::Prepared, Self::Dispatching) | (Self::Dispatching, Self::Observing | Self::Retryable | Self::Reconciling) | (Self::Observing, Self::CanonicalOutcome | Self::Reconciling) | (Self::Retryable, Self::Dispatching | Self::Reconciling | Self::ManualResolution) | (Self::Reconciling, Self::Observing | Self::CanonicalOutcome | Self::Retryable | Self::ManualResolution)) } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCommitDisposition { DurablyRecorded, NotCommittedRetryable, Indeterminate }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRef([u8; 32]);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeRef([u8; 32]);
#[allow(clippy::missing_errors_doc)]
impl CommandRef { pub fn new(value: [u8;32]) -> Result<Self, SecurityStateError> { if value == [0;32] { Err(SecurityStateError::InvalidIdentity) } else { Ok(Self(value)) } } }
#[allow(clippy::missing_errors_doc)]
impl OutcomeRef { pub fn new(value: [u8;32]) -> Result<Self, SecurityStateError> { if value == [0;32] { Err(SecurityStateError::InvalidIdentity) } else { Ok(Self(value)) } } }
pub struct MutationTransitionMetadata { runtime: Option<RuntimeCommitDisposition>, command: Option<CommandRef>, outcome: Option<OutcomeRef>, recovery_summary: String, timestamp: u64 }
#[allow(clippy::missing_errors_doc, clippy::cast_possible_wrap)]
impl MutationTransitionMetadata {
    pub fn new(runtime: Option<RuntimeCommitDisposition>, command: Option<CommandRef>, outcome: Option<OutcomeRef>, recovery_summary: impl Into<String>, timestamp: u64) -> Result<Self, SecurityStateError> { let recovery_summary = recovery_summary.into(); if recovery_summary.len() > 256 || recovery_summary.bytes().any(|byte| byte < 0x20) || timestamp > i64::MAX as u64 { return Err(SecurityStateError::InvalidTransition); } Ok(Self { runtime, command, outcome, recovery_summary, timestamp }) }
    pub(crate) fn runtime(&self) -> Option<&'static str> { self.runtime.map(|value| match value { RuntimeCommitDisposition::DurablyRecorded => "durably_recorded", RuntimeCommitDisposition::NotCommittedRetryable => "not_committed_retryable", RuntimeCommitDisposition::Indeterminate => "indeterminate" }) }
    pub(crate) fn command(&self) -> Option<&[u8;32]> { self.command.as_ref().map(|value| &value.0) }
    pub(crate) fn outcome(&self) -> Option<&[u8;32]> { self.outcome.as_ref().map(|value| &value.0) }
    pub(crate) fn summary(&self) -> &str { &self.recovery_summary }
    pub(crate) const fn timestamp(&self) -> i64 { self.timestamp as i64 }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationRecord { pub(crate) identity: MutationIdentity, pub(crate) client_state: ClientMutationDisposition, pub(crate) runtime_disposition: Option<RuntimeCommitDisposition>, pub(crate) command_ref: Option<CommandRef>, pub(crate) outcome_ref: Option<OutcomeRef> }
pub struct AnchoredMutationPermit { pub(crate) record: MutationRecord, pub(crate) anchor: SecurityAnchorV1 }
#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl AnchoredMutationPermit { pub fn generation(&self) -> u64 { self.anchor.generation } pub fn disposition(&self) -> ClientMutationDisposition { self.record.client_state } }
pub struct Anchored<T> { pub value: T, pub anchor: SecurityAnchorV1 }
#[derive(Clone)]
pub(crate) struct SecurityContext { pub profile: [u8; 32], pub database: [u8; 32], pub poisoned: bool }

#[derive(Debug, Error)]
pub enum SecurityStateError {
    #[error("security identity conflicts with a prior record")] IdentityConflict,
    #[error("security state transition is invalid")] InvalidTransition,
    #[error("security anchor does not match committed database state")] AnchorMismatch,
    #[error("security anchor could not be advanced")] AnchorAdvanceFailed,
    #[error("security storage is unavailable")] StorageUnavailable,
    #[error("security mutation identity is invalid")] InvalidIdentity,
    #[error("security database admission failed")] AdmissionFailed,
    #[error("local database open failed")] Open(#[source] StoreOpenError),
    #[error("security storage is unavailable")] Storage(#[from] rusqlite::Error),
    #[error("secure store failed")] SecureStore(#[from] gocode_secure_store::SecureStoreError),
}
