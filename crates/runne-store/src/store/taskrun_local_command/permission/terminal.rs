use super::model::now_ms;
use crate::store::StoreTransaction;
use runne_application::{
    commands::CommandOutcome,
    permission_modes::{LocalCommandPermissionBindingV1, ModeSelection},
    ports::{
        CommandCommit, CommitError, CommitResult, EventStoreError, StorageFailureKind,
        TaskRunAssignmentIdentity,
    },
    project_trust::ProjectTrustProjectId,
};
use runne_platform::local_command_linux::{LinuxLeaderExitKindV1, PermissionChildV1};
use rusqlite::Transaction;

/// Bounded output collected from this exact child by the X2 supervisor.
pub struct LocalCommandPermissionTerminalOutputV1 {
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) stdout_observed: i64,
    pub(super) stderr_observed: i64,
    pub(super) stdout_truncated: bool,
    pub(super) stderr_truncated: bool,
}

impl LocalCommandPermissionTerminalOutputV1 {
    /// Validates output facts before they can be retained in the terminal receipt.
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor validates both bounded streams and their separate EOF, truncation, and overflow facts"
    )]
    pub fn new(
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        stdout_observed: u64,
        stderr_observed: u64,
        stdout_truncated: bool,
        stderr_truncated: bool,
        stdout_eof: bool,
        stderr_eof: bool,
        observed_overflowed: bool,
    ) -> Result<Self, EventStoreError> {
        let stdout_observed =
            i64::try_from(stdout_observed).map_err(|_| EventStoreError::CorruptData)?;
        let stderr_observed =
            i64::try_from(stderr_observed).map_err(|_| EventStoreError::CorruptData)?;
        if stdout.len() > 65_536
            || stderr.len() > 65_536
            || stdout_observed < stdout.len() as i64
            || stderr_observed < stderr.len() as i64
            || stdout_truncated != (stdout_observed > stdout.len() as i64)
            || stderr_truncated != (stderr_observed > stderr.len() as i64)
            || !stdout_eof
            || !stderr_eof
            || observed_overflowed
        {
            return Err(EventStoreError::CorruptData);
        }
        Ok(Self {
            stdout,
            stderr,
            stdout_observed,
            stderr_observed,
            stdout_truncated,
            stderr_truncated,
        })
    }
}

impl StoreTransaction {
    /// Commits the taskrun terminal event and all V68/V49 facts in its canonical UoW.
    pub fn commit_local_command_permission_terminal(
        &self,
        payload: CommandCommit,
        identity: &TaskRunAssignmentIdentity,
        binding: &LocalCommandPermissionBindingV1,
        child: &PermissionChildV1<'_>,
        output: LocalCommandPermissionTerminalOutputV1,
    ) -> Result<CommitResult, CommitError> {
        if identity != binding.assignment()
            || child.original_binding() != binding
            || !child.was_released()
        {
            return Err(terminal_integrity_error());
        }
        let project = ProjectTrustProjectId::from_bytes(*binding.project_id().as_bytes());
        let owner = self
            .inner
            .permission_owner
            .as_ref()
            .ok_or_else(terminal_unavailable_error)?;
        let lease = owner
            .acquire_effect_lease(&self.runtime_authority_id, project)
            .map_err(|_| terminal_unavailable_error())?;
        let trust = lease.snapshot().map_err(|_| terminal_unavailable_error())?;
        let scope = binding.selection().scope.clone();
        if !trust.is_valid() {
            return Err(terminal_integrity_error());
        }
        let current_selection = self
            .load_permission_mode_selection(&scope, &scope.principal_id)
            .map_err(|_| terminal_integrity_error())?;
        let policy_stop = current_selection != *binding.selection()
            || trust != binding.closed_rules_snapshot()
            || trust.record.status
                == runne_application::project_trust::ProjectTrustStatus::Untrusted
            || current_selection
                .expires_at_unix_ms
                .is_some_and(|expiry| expiry <= now_ms());
        let policy_stop = policy_stop || binding.approval().expires_at_unix_ms <= now_ms();
        let terminal = PermissionTerminalCommitV1 {
            identity,
            binding,
            child,
            output,
            trust,
            current_selection,
            policy_stop,
        };
        let result = self.commit_permission_terminal_impl(payload, terminal);
        drop(lease);
        result
    }
}

pub(crate) struct PermissionTerminalCommitV1<'child, 'area> {
    pub(super) identity: &'child TaskRunAssignmentIdentity,
    pub(super) binding: &'child LocalCommandPermissionBindingV1,
    pub(super) child: &'child PermissionChildV1<'area>,
    pub(super) output: LocalCommandPermissionTerminalOutputV1,
    pub(super) trust: runne_application::project_trust::ProjectTrustEffectPolicySnapshot,
    pub(super) current_selection: ModeSelection,
    pub(super) policy_stop: bool,
}

impl PermissionTerminalCommitV1<'_, '_> {
    pub(crate) fn root_fence_request(
        &self,
    ) -> crate::store::taskrun_local_command::PermissionRootFenceRequestV1 {
        let binding = self.binding;
        crate::store::taskrun_local_command::PermissionRootFenceRequestV1::new(
            binding.selection().scope.workspace_id,
            binding.workspace_version(),
            binding.admitted_root_version(),
            *binding.held_root_identity_digest().as_bytes(),
        )
    }
}

pub(crate) struct PermissionTerminalDuplicateFacts {
    pub(super) binding_digest: [u8; 32],
    pub(super) area_identity: [u8; 100],
    pub(super) exit_kind: LinuxLeaderExitKindV1,
    pub(super) legacy_exit_code: i32,
    pub(super) terminal_version: u64,
}

pub(crate) struct PermissionTerminalProof {
    pub(crate) binding_digest: [u8; 32],
    pub(crate) area_identity: [u8; 100],
    pub(crate) event_id: runne_domain::id::EventId,
    pub(crate) terminal_version: u64,
    pub(crate) exit_kind: LinuxLeaderExitKindV1,
    pub(crate) legacy_exit_code: i32,
    pub(crate) stopped: bool,
}

pub(crate) fn validate_duplicate(
    tx: &Transaction<'_>,
    terminal: &PermissionTerminalCommitV1<'_, '_>,
    payload: &CommandCommit,
    stored_result: &CommandOutcome,
) -> Result<(), CommitError> {
    let facts = super::terminal_write::verify_duplicate_rows(tx, terminal, payload)?;
    super::stop::verify_duplicate_event(tx, terminal, payload, stored_result, &facts)
}

pub(super) fn terminal_integrity_error() -> CommitError {
    CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)
}

pub(super) fn terminal_unavailable_error() -> CommitError {
    CommitError::StorageFailure(StorageFailureKind::Unavailable)
}
