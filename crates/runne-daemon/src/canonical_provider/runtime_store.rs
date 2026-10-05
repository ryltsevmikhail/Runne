use std::sync::Arc;

use runne_application::provider::{
    ProviderExecutionError, ProviderExecutionStore, ProviderJournalAppendOutcome,
    ProviderJournalAppendRequest, ProviderJournalKeyBinding, ProviderPollRequest,
    ProviderRemoteAttemptBinding, ProviderRemoteAttemptPage, ProviderRemoteAttemptRecord,
    ProviderRemoteIdentityRecord, ProviderRemoteRecoveryStore, ProviderRemoteRequestIntent,
    ProviderRemoteTerminalRecord, ProviderTerminalCommitOutcome, ProviderTerminalOutboxRecord,
    ProviderTerminalPricingBinding,
};
use runne_provider::{
    DispatchAttemptId, ProviderDispatchClaim, ProviderRecoveryOperation, RemoteResponseId,
};
use runne_runtime::provider_execution::{
    ProviderTerminalCommitRequest, ProviderTerminalPersistence, ProviderTerminalUnknownSelector,
    ProviderUnknownTerminalAuthenticator,
};

use super::{RuntimeStoreDecorator, SqliteProviderExecutionStore};

/// Sized runtime view over the independently typed execution and terminal ports.
pub(super) struct DaemonProviderRuntimeStore {
    execution: Arc<dyn ProviderExecutionStore>,
    terminal: Arc<dyn ProviderTerminalPersistence>,
    remote: Arc<SqliteProviderExecutionStore>,
}

impl DaemonProviderRuntimeStore {
    pub(super) fn new(
        execution: Arc<dyn ProviderExecutionStore>,
        terminal: Arc<dyn ProviderTerminalPersistence>,
        remote: Arc<SqliteProviderExecutionStore>,
    ) -> Self {
        Self {
            execution,
            terminal,
            remote,
        }
    }
}

pub(super) fn compose_runtime_store(
    concrete: Arc<SqliteProviderExecutionStore>,
    runtime_generation: u64,
    decorator: Option<Arc<RuntimeStoreDecorator>>,
) -> Arc<DaemonProviderRuntimeStore> {
    let remote = Arc::clone(&concrete);
    let (execution, terminal) = match decorator {
        None => {
            let execution: Arc<dyn ProviderExecutionStore> = concrete.clone();
            let terminal: Arc<dyn ProviderTerminalPersistence> = concrete;
            (execution, terminal)
        }
        Some(decorate) => decorate(concrete, runtime_generation),
    };
    Arc::new(DaemonProviderRuntimeStore::new(execution, terminal, remote))
}

impl ProviderRemoteRecoveryStore for DaemonProviderRuntimeStore {
    fn remote_cancel_requested(
        &self,
        binding: &ProviderRemoteAttemptBinding,
    ) -> Result<bool, ProviderExecutionError> {
        self.remote.remote_cancel_requested(binding)
    }
    fn find_remote_attempt(
        &self,
        taskrun: runne_domain::id::TaskRunId,
        attempt: runne_domain::id::AttemptId,
    ) -> Result<Option<DispatchAttemptId>, ProviderExecutionError> {
        self.remote.find_remote_attempt(taskrun, attempt)
    }
    fn find_remote_attempt_history(
        &self,
        taskrun: runne_domain::id::TaskRunId,
        attempt: runne_domain::id::AttemptId,
    ) -> Result<Option<DispatchAttemptId>, ProviderExecutionError> {
        self.remote.find_remote_attempt_history(taskrun, attempt)
    }
    fn load_remote_attempt_history(
        &self,
        taskrun: runne_domain::id::TaskRunId,
        attempt: runne_domain::id::AttemptId,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteAttemptRecord>,
        ProviderExecutionError,
    > {
        self.remote.load_remote_attempt_history(taskrun, attempt)
    }
    fn load_remote_call_digest_version(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<runne_provider::ProviderCallDigestVersion, ProviderExecutionError> {
        self.remote.load_remote_call_digest_version(attempt)
    }
    fn scan_remote_attempts(
        &self,
        after: Option<DispatchAttemptId>,
        limit: usize,
    ) -> Result<ProviderRemoteAttemptPage, ProviderExecutionError> {
        self.remote.scan_remote_attempts(after, limit)
    }
    fn resolve_remote_attempt_binding(
        &self,
        claim: &ProviderDispatchClaim,
        provider: &runne_provider::ProviderId,
        realm: &runne_provider::ProviderId,
        profile: &str,
    ) -> Result<ProviderRemoteAttemptBinding, ProviderExecutionError> {
        self.remote
            .resolve_remote_attempt_binding(claim, provider, realm, profile)
    }
    fn issue_remote_operation_proof(
        &self,
        binding: &ProviderRemoteAttemptBinding,
        response: &RemoteResponseId,
        operation: ProviderRecoveryOperation,
    ) -> Result<runne_provider::ProviderRemoteOperationProof, ProviderExecutionError> {
        self.remote
            .issue_remote_operation_proof(binding, response, operation)
    }
    fn validate_remote_operation_proof(
        &self,
        proof: &runne_provider::ProviderRemoteOperationProof,
        response: &RemoteResponseId,
    ) -> Result<(), ProviderExecutionError> {
        self.remote.validate_remote_operation_proof(proof, response)
    }
    fn persist_remote_request(
        &self,
        request: &ProviderRemoteRequestIntent,
    ) -> Result<(), ProviderExecutionError> {
        self.remote.persist_remote_request(request)
    }
    fn commit_remote_response_id(
        &self,
        response: &ProviderRemoteIdentityRecord,
    ) -> Result<(), ProviderExecutionError> {
        self.remote.commit_remote_response_id(response)
    }
    fn load_remote_identity(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<
        Option<(
            ProviderRemoteRequestIntent,
            Option<ProviderRemoteIdentityRecord>,
        )>,
        ProviderExecutionError,
    > {
        self.remote.load_remote_identity(attempt)
    }
    fn commit_remote_terminal_artifact(
        &self,
        artifact: &ProviderRemoteTerminalRecord,
    ) -> Result<(), ProviderExecutionError> {
        self.remote.commit_remote_terminal_artifact(artifact)
    }
    fn commit_remote_terminal_artifact_with_proof(
        &self,
        artifact: &ProviderRemoteTerminalRecord,
        proof: &runne_provider::ProviderRemoteOperationProof,
    ) -> Result<(), ProviderExecutionError> {
        self.remote
            .commit_remote_terminal_artifact_with_proof(artifact, proof)
    }
    fn commit_remote_operation_observation(
        &self,
        proof: &runne_provider::ProviderRemoteOperationProof,
        status: runne_provider::ProviderRemoteResponseStatus,
    ) -> Result<(), ProviderExecutionError> {
        self.remote
            .commit_remote_operation_observation(proof, status)
    }
    fn load_remote_terminal_artifact(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<Option<ProviderRemoteTerminalRecord>, ProviderExecutionError> {
        self.remote.load_remote_terminal_artifact(attempt)
    }
    fn load_remote_attempt(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<Option<ProviderRemoteAttemptRecord>, ProviderExecutionError> {
        self.remote.load_remote_attempt(attempt)
    }
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
    fn activate_journal_key_with_keyring(
        &self,
        keyring: &dyn runne_secure_store::ProviderJournalKeyring,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.execution
            .activate_journal_key_with_keyring(keyring, key)
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
    fn revalidate_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        self.execution.revalidate_provider_poll(request)
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
    fn pending_tool_proposal_outbox_for_attempt(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.execution
            .pending_tool_proposal_outbox_for_attempt(attempt_id)
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

#[cfg(test)]
#[path = "runtime_store/tests.rs"]
mod tests;

mod terminal;
