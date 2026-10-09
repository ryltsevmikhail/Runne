use super::super::event_guard::*;
use super::super::parse_helpers::*;
use super::super::*;
include!("commit/entry.rs");
include!("commit/transaction.rs");
include!("commit/append.rs");

#[cfg(target_os = "linux")]
impl StoreTransaction {
    pub(crate) fn commit_permission_terminal_impl(
        &self,
        payload: CommandCommit,
        terminal: crate::store::taskrun_local_command::permission::PermissionTerminalCommitV1<
            '_,
            '_,
        >,
    ) -> Result<CommitResult, CommitError> {
        if payload.events.is_empty() || payload.events.len() > MAX_EVENTS_PER_COMMIT {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let taskrun_id = match payload.events[0].correlation_id() {
            AggregateId::TaskRun(id) => *id,
            _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
        };
        if payload
            .events
            .iter()
            .any(|event| event.correlation_id() != &AggregateId::TaskRun(taskrun_id))
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let request = terminal.root_fence_request();
        let owner = self
            .inner
            .permission_owner
            .as_ref()
            .ok_or_else(|| storage_failure(StorageFailureKind::Unavailable))?;
        let _root_guard = owner
            .acquire_root_fence(&self.runtime_authority_id, &request)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        self.commit_transaction_with_permission_terminal(
            tx,
            payload,
            taskrun_id,
            taskrun_id.as_bytes(),
            Some(terminal),
        )
    }
}
