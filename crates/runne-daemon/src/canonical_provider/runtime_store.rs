use std::sync::Arc;

use runne_application::provider::{
    ProviderExecutionError, ProviderExecutionStore, ProviderJournalAppendOutcome,
    ProviderJournalAppendRequest, ProviderJournalKeyBinding, ProviderPollRequest,
    ProviderTerminalCommitOutcome, ProviderTerminalOutboxRecord, ProviderTerminalPricingBinding,
};
use runne_provider::DispatchAttemptId;
use runne_runtime::provider_execution::{
    ProviderTerminalCommitRequest, ProviderTerminalPersistence,
};

use super::{RuntimeStoreDecorator, SqliteProviderExecutionStore};

/// Sized runtime view over the independently typed execution and terminal ports.
pub(super) struct DaemonProviderRuntimeStore {
    execution: Arc<dyn ProviderExecutionStore>,
    terminal: Arc<dyn ProviderTerminalPersistence>,
}

impl DaemonProviderRuntimeStore {
    pub(super) fn new(
        execution: Arc<dyn ProviderExecutionStore>,
        terminal: Arc<dyn ProviderTerminalPersistence>,
    ) -> Self {
        Self {
            execution,
            terminal,
        }
    }
}

pub(super) fn compose_runtime_store(
    concrete: Arc<SqliteProviderExecutionStore>,
    runtime_generation: u64,
    decorator: Option<Arc<RuntimeStoreDecorator>>,
) -> Arc<DaemonProviderRuntimeStore> {
    let (execution, terminal) = match decorator {
        None => {
            let execution: Arc<dyn ProviderExecutionStore> = concrete.clone();
            let terminal: Arc<dyn ProviderTerminalPersistence> = concrete;
            (execution, terminal)
        }
        Some(decorate) => decorate(concrete, runtime_generation),
    };
    Arc::new(DaemonProviderRuntimeStore::new(execution, terminal))
}

impl ProviderExecutionStore for DaemonProviderRuntimeStore {
    fn active_journal_key_binding(
        &self,
    ) -> Result<Option<ProviderJournalKeyBinding>, ProviderExecutionError> {
        self.execution.active_journal_key_binding()
    }
    fn activate_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.execution.activate_journal_key(key)
    }
    fn journal_key_reference_count(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError> {
        self.execution.journal_key_reference_count(key)
    }
    fn remove_retired_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.execution.remove_retired_journal_key(key)
    }
    fn begin_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        self.execution.begin_provider_poll(request)
    }
    fn append_encrypted_event(
        &self,
        request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        self.execution.append_encrypted_event(request)
    }
    fn load_encrypted_events(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        self.execution.load_encrypted_events(attempt_id)
    }
    fn load_terminal_pricing_binding(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
        self.execution.load_terminal_pricing_binding(attempt_id)
    }
    fn pending_terminal_outbox(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.execution.pending_terminal_outbox()
    }
    fn acknowledge_terminal_outbox(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), ProviderExecutionError> {
        self.execution
            .acknowledge_terminal_outbox(outbox_id, receipt_digest)
    }
    fn mark_execution_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderExecutionError> {
        self.execution
            .mark_execution_uncertain(attempt_id, fencing_token)
    }
}

impl ProviderTerminalPersistence for DaemonProviderRuntimeStore {
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        self.terminal.commit_terminal(request)
    }
}
