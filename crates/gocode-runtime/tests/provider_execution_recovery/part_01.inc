use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::provider::{
    ProviderAuthorityIssueRequest, ProviderExecutionError, ProviderExecutionStore,
    ProviderJournalAppendOutcome, ProviderJournalAppendRequest, ProviderJournalKeyBinding,
    ProviderPollRequest, ProviderTerminalCommitOutcome, ProviderTerminalOutboxRecord,
    ProviderTerminalPricingBinding,
};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, ModelRef, PrepareError,
    PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest, ProviderCall,
    ProviderCallDigestVersion, ProviderCallId, ProviderFinishReason, ProviderFuture, ProviderId,
    ProviderPort, ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId,
    ProviderStreamItem, ProviderTerminalDisposition, ProviderUsage, ReconcileRequest,
    ReconciliationDisposition, StreamCursor, StreamError,
};
use gocode_provider_openai::OpenAiResponsesTextProfile;
use gocode_runtime::provider_execution::{
    ProviderEventJournalContext, ProviderPricedUsage, ProviderTerminalApplicationError,
    ProviderTerminalCommitRequest, ProviderTerminalOutboxApplication, ProviderTerminalPersistence,
    ProviderTerminalPricing, ProviderTerminalPricingError, RuntimeProviderExecution,
    RuntimeProviderExecutionError,
};
use gocode_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};
use gocode_store::provider::{
    MarkProviderStreaming, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
    ProviderRuntimeAuthorityConfig, SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
#[derive(Default)]
struct MemoryKeyring {
    keys: Mutex<HashMap<ProviderJournalKeyRef, [u8; 32]>>,
    loads: AtomicUsize,
}
impl MemoryKeyring {
    fn remove_without_proof(&self, key_ref: ProviderJournalKeyRef) {
        self.keys.lock().unwrap().remove(&key_ref);
    }
}
impl ProviderJournalKeyring for MemoryKeyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn provider_journal_key_status(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(if self.keys.lock().unwrap().contains_key(&key_ref) {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }

    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        let bytes = key.with_bytes(|bytes| *bytes);
        let mut keys = self.keys.lock().unwrap();
        if let Some(existing) = keys.get(&key.key_ref()) {
            return if *existing == bytes {
                Ok(())
            } else {
                Err(SecureStoreError::CorruptProviderJournalKey)
            };
        }
        keys.insert(key.key_ref(), bytes);
        Ok(())
    }

    fn load_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        let bytes = self
            .keys
            .lock()
            .unwrap()
            .get(&key_ref)
            .copied()
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)?;
        ProviderJournalKeyMaterial::new(key_ref, bytes)
    }

    fn delete_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
        _proof: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        self.keys
            .lock()
            .unwrap()
            .remove(&key_ref)
            .map(|_| ())
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)
    }
}
#[test]
fn existing_key_preflight_validates_metadata_without_loading_key_bytes() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    let key = writer.create_and_activate_key([1; 16], 7, 1).unwrap();
    keyring.loads.store(0, Ordering::SeqCst);

    let restarted = runtime(&keyring, fixture.execution.as_ref());
    assert_eq!(restarted.preflight_existing_active_key([1; 16], 7), Ok(key));
    assert_eq!(keyring.loads.load(Ordering::SeqCst), 0);
}
struct Fixture {
    execution: Arc<SqliteProviderExecutionStore>,
    attempt_id: gocode_provider::DispatchAttemptId,
    fencing_token: u64,
    path: std::path::PathBuf,
}

fn fixture() -> Fixture {
    fixture_with_input_tokens(512)
}

fn fixture_with_input_tokens(requested_input_tokens: u64) -> Fixture {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.keep().join("provider-runtime-recovery.sqlite");
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-31",
        )
        .unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let prepared_record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [2; 32],
    };
    let dispatch = SqliteProviderDispatchStore::open(&path).unwrap();
    dispatch.persist_prepared(&prepared_record).unwrap();
    let execution = Arc::new(SqliteProviderExecutionStore::open(&path).unwrap());
    execution
        .install_runtime_authority(&ProviderRuntimeAuthorityConfig {
            runtime_authority_id: [1; 16],
            database_generation: 7,
            principal_id: "principal-1".to_owned(),
            owner_id: "runtime-owner-1".to_owned(),
            scope: "provider.dispatch".to_owned(),
            generation: 11,
            fencing_token: 13,
            capability_grant_id: "grant-provider-network-1".to_owned(),
            capability_revision: 2,
            capability_allowed: true,
            capability_revocation_epoch: 1,
            approval_id: "approval-provider-network-1".to_owned(),
            approval_revision: 3,
            approval_allowed: true,
            approval_revocation_epoch: 1,
            profile_digest: [2; 32],
            pricing_revision_digest: [3; 32],
            activation_binding_kind:
                gocode_application::provider::ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    let ProviderAuthorityIssueOutcome::Winner(admitted) = execution
        .issue(&ProviderAuthorityIssueRequest {
            principal_id: "principal-1".to_owned(),
            conversation_id: ConversationId::from_bytes([6; 16]),
            taskrun_id: TaskRunId::from_bytes([7; 16]),
            execution_attempt_id: AttemptId::from_bytes([8; 16]),
            prepared: ContractPreparedProviderRecord {
                call_id: prepared_record.call_id,
                call_digest_version: prepared_record.call_digest_version,
                prepared_digest: prepared_record.prepared_digest,
                render_digest: prepared_record.render_digest,
                profile_digest: prepared_record.profile_digest,
            },
            pricing_revision_digest: [3; 32],
            requested_input_tokens,
            requested_output_tokens: 1_024,
            max_cost_micros: 50_000,
            currency: "USD".to_owned(),
            provider_idempotency_key: "provider-runtime-recovery-1".to_owned(),
        })
        .unwrap()
    else {
        panic!("first issue must win")
    };
    dispatch
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: admitted.claim().attempt_id,
            fencing_token: admitted.claim().fencing_token,
            stream_id: ProviderStreamId::from_bytes([9; 16]),
        })
        .unwrap();
    Fixture {
        execution,
        attempt_id: admitted.claim().attempt_id,
        fencing_token: admitted.claim().fencing_token,
        path,
    }
}

fn context(fixture: &Fixture) -> ProviderEventJournalContext {
    ProviderEventJournalContext {
        attempt_id: fixture.attempt_id,
        fencing_token: fixture.fencing_token,
        call_digest_version: gocode_provider::ProviderCallDigestVersion::V2,
        profile_digest: [2; 32],
        runtime_generation: 11,
    }
}

fn successful_events(output: &str) -> Vec<ProviderStreamEvent> {
    vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: output.to_owned(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(500, 900, 0, 0).unwrap(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ]
}

async fn poll_events<P: ProviderTerminalPricing>(
    runtime: &RuntimeProviderExecution<'_, MemoryKeyring, SqliteProviderExecutionStore, P>,
    fixture: &Fixture,
    events: Vec<ProviderStreamEvent>,
) {
    let provider = CommitCheckingProvider {
        store: Arc::clone(&fixture.execution),
        attempt_id: fixture.attempt_id,
        events: events.clone(),
    };
    let stream_id = ProviderStreamId::from_bytes([9; 16]);
    for (sequence, expected) in events.iter().enumerate() {
        let item = runtime
            .next_and_commit(
                &provider,
                &stream_id,
                StreamCursor::new(sequence as u64),
                &context(fixture),
            )
            .await
            .unwrap();
        assert_eq!(item.event(), expected);
    }
}

struct AllowingGuard;

impl ProhibitedContentPort for AllowingGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}
