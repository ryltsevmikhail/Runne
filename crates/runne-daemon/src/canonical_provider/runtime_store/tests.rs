use super::*;
use runne_application::provider::{
    ProviderEncryptedPayload, ProviderExecutionError, ProviderExecutionStore,
    ProviderJournalAppendOutcome, ProviderJournalAppendRequest, ProviderJournalKeyBinding,
    ProviderPollRequest, ProviderTerminalApplicationKind, ProviderTerminalOutboxRecord,
    ProviderTerminalOutboxSource, ProviderTerminalPricingBinding,
};
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::DispatchAttemptId;
use runne_provider::ProviderCallDigestVersion;
use runne_store::provider::SqliteProviderExecutionStore;
use std::sync::Arc;

struct TypedOutboxExecution {
    record: ProviderTerminalOutboxRecord,
}

impl ProviderExecutionStore for TypedOutboxExecution {
    fn activate_journal_key(
        &self,
        _: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        Ok(())
    }
    fn journal_key_reference_count(
        &self,
        _: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError> {
        Ok(0)
    }
    fn remove_retired_journal_key(
        &self,
        _: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        Ok(())
    }
    fn begin_provider_poll(&self, _: &ProviderPollRequest) -> Result<(), ProviderExecutionError> {
        Ok(())
    }
    fn append_encrypted_event(
        &self,
        _: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }
    fn load_encrypted_events(
        &self,
        _: DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        Ok(Vec::new())
    }
    fn load_terminal_pricing_binding(
        &self,
        _: DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }
    fn pending_terminal_outbox(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        Ok(Vec::new())
    }
    fn pending_tool_proposal_outbox_for_attempt(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        Ok((self.record.attempt_id == attempt)
            .then(|| self.record.clone())
            .into_iter()
            .collect())
    }
    fn acknowledge_terminal_outbox(
        &self,
        _: [u8; 16],
        _: [u8; 32],
    ) -> Result<(), ProviderExecutionError> {
        Ok(())
    }
    fn mark_execution_uncertain(
        &self,
        _: DispatchAttemptId,
        _: u64,
    ) -> Result<(), ProviderExecutionError> {
        Ok(())
    }
}

fn tool_outbox_record() -> ProviderTerminalOutboxRecord {
    ProviderTerminalOutboxRecord {
        application_kind: ProviderTerminalApplicationKind::ToolProposal,
        outbox_id: [1; 16],
        attempt_id: DispatchAttemptId::from_bytes([2; 16]),
        source: ProviderTerminalOutboxSource::StreamJournal,
        fencing_token: 3,
        principal_id: "fixture-principal".into(),
        conversation_id: ConversationId::from_bytes([4; 16]),
        taskrun_id: TaskRunId::from_bytes([5; 16]),
        execution_attempt_id: AttemptId::from_bytes([6; 16]),
        terminal_sequence: 7,
        call_digest_version: ProviderCallDigestVersion::V1,
        key: ProviderJournalKeyBinding::new([8; 16], 1, [9; 16], 1).unwrap(),
        encrypted_output: ProviderEncryptedPayload::new([10; 12], vec![0; 16], 0, [11; 32])
            .unwrap(),
        runtime_generation: 12,
        profile_digest: [13; 32],
        settlement_digest: [14; 32],
        application_idempotency_key: "tool-outbox-fixture".into(),
    }
}

#[test]
fn composed_runtime_store_forwards_typed_tool_outbox_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let remote = Arc::new(
        SqliteProviderExecutionStore::open(&directory.path().join("provider.sqlite3")).unwrap(),
    );
    let record = tool_outbox_record();
    let attempt = record.attempt_id;
    let terminal: Arc<dyn ProviderTerminalPersistence> = remote.clone();
    let store = DaemonProviderRuntimeStore::new(
        Arc::new(TypedOutboxExecution {
            record: record.clone(),
        }),
        terminal,
        remote,
    );

    let typed =
        ProviderExecutionStore::pending_tool_proposal_outbox_for_attempt(&store, attempt).unwrap();
    let text_path =
        ProviderExecutionStore::pending_terminal_outbox_for_attempt(&store, attempt).unwrap();
    assert_eq!(typed, vec![record]);
    assert!(text_path.is_empty());
}
