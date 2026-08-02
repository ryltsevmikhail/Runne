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

struct DenyingGuard;

impl ProhibitedContentPort for DenyingGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Prohibited { policy_epoch: 1 })
    }
}

struct FixedPricing;

impl ProviderTerminalPricing for FixedPricing {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        assert_eq!(pricing_revision_digest, &[3; 32]);
        assert_eq!(profile_digest, &[2; 32]);
        assert_eq!(usage, ProviderUsage::new(500, 900, 0, 0).unwrap());
        ProviderPricedUsage::new(40_000, "USD".to_owned())
    }
}

struct ZeroInputPricing;

impl ProviderTerminalPricing for ZeroInputPricing {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        assert_eq!(pricing_revision_digest, &[3; 32]);
        assert_eq!(profile_digest, &[2; 32]);
        assert_eq!(usage, ProviderUsage::new(0, 900, 0, 0).unwrap());
        ProviderPricedUsage::new(30_000, "USD".to_owned())
    }
}

static FIXED_PRICING: FixedPricing = FixedPricing;
static ZERO_INPUT_PRICING: ZeroInputPricing = ZeroInputPricing;
static ALLOWING_GUARD: AllowingGuard = AllowingGuard;
static DENYING_GUARD: DenyingGuard = DenyingGuard;

fn runtime<'a, S>(
    keyring: &'a MemoryKeyring,
    store: &'a S,
) -> RuntimeProviderExecution<'a, MemoryKeyring, S, FixedPricing>
where
    S: ProviderExecutionStore + ProviderTerminalPersistence,
{
    RuntimeProviderExecution::new(keyring, store, &FIXED_PRICING, &ALLOWING_GUARD)
}

#[tokio::test(flavor = "current_thread")]
async fn aead_journal_recovers_exact_event_and_plaintext_is_absent_from_database_files() {
    const MARKER: &str = "provider-journal-plaintext-marker-71";
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: MARKER.to_owned(),
            },
        )
        .unwrap(),
    ];

    poll_events(&runtime, &fixture, events.clone()).await;
    assert_eq!(runtime.recover_events(fixture.attempt_id).unwrap(), events);
    for path in [
        fixture.path.clone(),
        fixture.path.with_extension("sqlite-wal"),
        fixture.path.with_extension("sqlite-shm"),
    ] {
        let bytes = std::fs::read(path).unwrap_or_default();
        assert!(
            !bytes
                .windows(MARKER.len())
                .any(|window| window == MARKER.as_bytes())
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn corrupt_ciphertext_and_missing_retired_key_fail_closed() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    let first_key = runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "recover-me".to_owned(),
            },
        )
        .unwrap(),
    ];
    poll_events(&runtime, &fixture, events.clone()).await;
    runtime.create_and_activate_key([1; 16], 7, 2).unwrap();
    assert_eq!(runtime.recover_events(fixture.attempt_id).unwrap(), events);

    keyring.remove_without_proof(
        ProviderJournalKeyRef::new(
            first_key.key_id(),
            first_key.key_version(),
            first_key.runtime_authority_id(),
            first_key.database_generation(),
        )
        .unwrap(),
    );
    assert_eq!(
        runtime.recover_events(fixture.attempt_id),
        Err(RuntimeProviderExecutionError::JournalKeyUnavailable)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_output_is_encrypted_recoverable_and_settled_only_after_receipt() {
    const OUTPUT: &[u8] = b"assembled-provider-output-marker-81";
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    poll_events(
        &runtime,
        &fixture,
        successful_events(std::str::from_utf8(OUTPUT).unwrap()),
    )
    .await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Replayed)
    );
    let pending = runtime.recover_pending_terminal_outputs().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].output(), OUTPUT);
    assert!(!format!("{:?}", pending[0]).contains(std::str::from_utf8(OUTPUT).unwrap()));

    runtime
        .acknowledge_terminal_output(pending[0].record().outbox_id, [32; 32])
        .unwrap();
    assert!(
        runtime
            .recover_pending_terminal_outputs()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn zero_input_reservation_admits_streams_and_settles_completed_usage() {
    let fixture = fixture_with_input_tokens(0);
    let keyring = MemoryKeyring::default();
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        fixture.execution.as_ref(),
        &ZERO_INPUT_PRICING,
        &ALLOWING_GUARD,
    );
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "zero-input-output".to_owned(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(0, 900, 0, 0).unwrap(),
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
    ];
    poll_events(&runtime, &fixture, events).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT input_tokens, output_tokens, charge_micros
                 FROM provider_accounting_settlements",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap(),
        (0, 900, 30_000)
    );
    let reservations = connection
        .prepare(
            "SELECT dimension, settled_amount
             FROM provider_budget_reservations ORDER BY dimension",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(reservations, vec![(1, 900), (2, 30_000)]);
}

#[tokio::test(flavor = "current_thread")]
async fn remote_failure_without_usage_consumes_full_reservation_without_conversation_outbox() {
    const PARTIAL: &str = "remote-failed-partial-must-not-be-applied-83";
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &DENYING_GUARD,
    );
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: PARTIAL.to_owned(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap(),
        ProviderStreamEvent::new(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::RemoteFailed,
                reason: ProviderFinishReason::Error,
            },
        )
        .unwrap(),
    ];
    poll_events(&runtime, &fixture, events).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Replayed)
    );
    assert!(
        runtime
            .recover_pending_terminal_outputs()
            .unwrap()
            .is_empty()
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT input_tokens, output_tokens, cached_input_tokens,
                        reasoning_output_tokens, charge_micros
                 FROM provider_accounting_settlements",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .unwrap(),
        (512, 1_024, 0, 0, 50_000)
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_encryption_nonces WHERE purpose = 2",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        5
    );
    let reservations = connection
        .prepare(
            "SELECT dimension, settled_amount
             FROM provider_budget_reservations ORDER BY dimension",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(reservations, vec![(1, 1_536), (2, 50_000)]);
    let database = std::fs::read(&fixture.path).unwrap();
    assert!(
        !database
            .windows(PARTIAL.len())
            .any(|window| window == PARTIAL.as_bytes())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn prohibited_terminal_output_creates_no_accounting_or_outbox() {
    const OUTPUT: &str = "registered-prohibited-provider-output-marker-82";
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &DENYING_GUARD,
    );
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    poll_events(&runtime, &fixture, successful_events(OUTPUT)).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Err(RuntimeProviderExecutionError::PolicyDenied)
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    for table in [
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "policy denial mutated {table}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_exact_profile_pricing_creates_no_accounting_or_outbox() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let openai_profile = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .unwrap();
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        fixture.execution.as_ref(),
        &openai_profile,
        &ALLOWING_GUARD,
    );
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    poll_events(
        &runtime,
        &fixture,
        successful_events("exact-pricing-mismatch"),
    )
    .await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Err(RuntimeProviderExecutionError::PricingUnavailable)
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    for table in [
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "pricing mismatch mutated {table}"
        );
    }
}

struct CommitCheckingProvider {
    store: Arc<SqliteProviderExecutionStore>,
    attempt_id: gocode_provider::DispatchAttemptId,
    events: Vec<ProviderStreamEvent>,
}

impl ProviderPort for CommitCheckingProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        digest_version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, digest_version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!("fixture stream is already durable") })
    }

    fn next<'a>(
        &'a self,
        _stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        if cursor.sequence() > 0 {
            let committed = self
                .store
                .load_encrypted_events(self.attempt_id)
                .expect("previous event remains readable");
            assert_eq!(
                committed.len(),
                cursor.sequence() as usize,
                "runtime polled the next provider frame before prior journal commit"
            );
        }
        let event = self.events[cursor.sequence() as usize].clone();
        Box::pin(async move { ProviderStreamItem::from_event(event) })
    }

    fn cancel(
        &self,
        _request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("fixture does not cancel") })
    }

    fn reconcile(
        &self,
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("fixture does not reconcile") })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn each_event_commit_precedes_the_next_adapter_poll() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ];
    let provider = CommitCheckingProvider {
        store: Arc::clone(&fixture.execution),
        attempt_id: fixture.attempt_id,
        events: events.clone(),
    };
    let stream_id = ProviderStreamId::from_bytes([9; 16]);

    for sequence in 0..2 {
        let item = runtime
            .next_and_commit(
                &provider,
                &stream_id,
                StreamCursor::new(sequence),
                &context(&fixture),
            )
            .await
            .unwrap();
        assert_eq!(item.event(), &events[sequence as usize]);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn provider_bytes_without_local_commit_freeze_attempt_as_uncertain() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    let provider = CommitCheckingProvider {
        store: Arc::clone(&fixture.execution),
        attempt_id: fixture.attempt_id,
        events: vec![ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap()],
    };

    assert_eq!(
        runtime
            .next_and_commit(
                &provider,
                &ProviderStreamId::from_bytes([9; 16]),
                StreamCursor::new(0),
                &context(&fixture),
            )
            .await,
        Err(RuntimeProviderExecutionError::JournalCommitLost)
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        6
    );
}

struct FailAppendAndFreezeStore {
    inner: Arc<SqliteProviderExecutionStore>,
}

impl ProviderExecutionStore for FailAppendAndFreezeStore {
    fn activate_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.activate_journal_key(key)
    }

    fn journal_key_reference_count(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError> {
        self.inner.journal_key_reference_count(key)
    }

    fn remove_retired_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.remove_retired_journal_key(key)
    }

    fn begin_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.begin_provider_poll(request)
    }

    fn append_encrypted_event(
        &self,
        _request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

    fn load_encrypted_events(
        &self,
        attempt_id: gocode_provider::DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        self.inner.load_encrypted_events(attempt_id)
    }

    fn load_terminal_pricing_binding(
        &self,
        attempt_id: gocode_provider::DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
        self.inner.load_terminal_pricing_binding(attempt_id)
    }

    fn pending_terminal_outbox(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.inner.pending_terminal_outbox()
    }

    fn acknowledge_terminal_outbox(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), ProviderExecutionError> {
        self.inner
            .acknowledge_terminal_outbox(outbox_id, receipt_digest)
    }

    fn mark_execution_uncertain(
        &self,
        _attempt_id: gocode_provider::DispatchAttemptId,
        _fencing_token: u64,
    ) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }
}

impl ProviderTerminalPersistence for FailAppendAndFreezeStore {
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        self.inner.commit_terminal(request)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn durable_poll_marker_blocks_repoll_when_append_and_freeze_both_fail() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let failing = FailAppendAndFreezeStore {
        inner: Arc::clone(&fixture.execution),
    };
    let writer = runtime(&keyring, &failing);
    writer.create_and_activate_key([1; 16], 7, 1).unwrap();
    let event = ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap();
    let provider = CommitCheckingProvider {
        store: Arc::clone(&fixture.execution),
        attempt_id: fixture.attempt_id,
        events: vec![event.clone()],
    };
    let stream_id = ProviderStreamId::from_bytes([9; 16]);

    assert_eq!(
        writer
            .next_and_commit(
                &provider,
                &stream_id,
                StreamCursor::new(0),
                &context(&fixture),
            )
            .await,
        Err(RuntimeProviderExecutionError::JournalCommitLost)
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM provider_poll_flights", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        3
    );
    drop(connection);

    let recovery = runtime(&keyring, fixture.execution.as_ref());
    assert_eq!(
        recovery
            .next_and_commit(
                &provider,
                &stream_id,
                StreamCursor::new(0),
                &context(&fixture),
            )
            .await,
        Err(RuntimeProviderExecutionError::RecoveryFrozen)
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        6
    );
}

struct FailFirstAcknowledgementStore {
    inner: Arc<SqliteProviderExecutionStore>,
    fail_acknowledgement: AtomicBool,
}

impl ProviderExecutionStore for FailFirstAcknowledgementStore {
    fn activate_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.activate_journal_key(key)
    }

    fn journal_key_reference_count(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError> {
        self.inner.journal_key_reference_count(key)
    }

    fn remove_retired_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.remove_retired_journal_key(key)
    }

    fn begin_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.begin_provider_poll(request)
    }

    fn append_encrypted_event(
        &self,
        request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        self.inner.append_encrypted_event(request)
    }

    fn load_encrypted_events(
        &self,
        attempt_id: gocode_provider::DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        self.inner.load_encrypted_events(attempt_id)
    }

    fn load_terminal_pricing_binding(
        &self,
        attempt_id: gocode_provider::DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
        self.inner.load_terminal_pricing_binding(attempt_id)
    }

    fn pending_terminal_outbox(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.inner.pending_terminal_outbox()
    }

    fn acknowledge_terminal_outbox(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), ProviderExecutionError> {
        if self.fail_acknowledgement.swap(false, Ordering::SeqCst) {
            return Err(ProviderExecutionError::StoreUnavailable);
        }
        self.inner
            .acknowledge_terminal_outbox(outbox_id, receipt_digest)
    }

    fn mark_execution_uncertain(
        &self,
        attempt_id: gocode_provider::DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderExecutionError> {
        self.inner
            .mark_execution_uncertain(attempt_id, fencing_token)
    }
}

impl ProviderTerminalPersistence for FailFirstAcknowledgementStore {
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        self.inner.commit_terminal(request)
    }
}

#[derive(Default)]
struct IdempotentTerminalApplication {
    calls: AtomicUsize,
    committed: Mutex<HashMap<String, Vec<u8>>>,
}

impl ProviderTerminalOutboxApplication for IdempotentTerminalApplication {
    fn complete_provider_terminal(
        &self,
        record: &ProviderTerminalOutboxRecord,
        output: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(record.principal_id, "principal-1");
        assert_eq!(record.conversation_id, ConversationId::from_bytes([6; 16]));
        assert_eq!(record.taskrun_id, TaskRunId::from_bytes([7; 16]));
        assert_eq!(record.execution_attempt_id, AttemptId::from_bytes([8; 16]));
        assert_eq!(record.fencing_token, 13);
        let mut committed = self
            .committed
            .lock()
            .map_err(|_| ProviderTerminalApplicationError::Unavailable)?;
        match committed.get(&record.application_idempotency_key) {
            Some(existing) if existing != output => Err(ProviderTerminalApplicationError::Conflict),
            Some(_) => Ok([77; 32]),
            None => {
                committed.insert(record.application_idempotency_key.clone(), output.to_vec());
                Ok([77; 32])
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn crash_after_application_commit_before_outbox_ack_replays_one_completion_identity() {
    const OUTPUT: &[u8] = b"idempotent-terminal-output-marker-92";
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.create_and_activate_key([1; 16], 7, 1).unwrap();
    poll_events(
        &writer,
        &fixture,
        successful_events(std::str::from_utf8(OUTPUT).unwrap()),
    )
    .await;
    writer.finalize_terminal_output(&context(&fixture)).unwrap();

    let store = FailFirstAcknowledgementStore {
        inner: Arc::clone(&fixture.execution),
        fail_acknowledgement: AtomicBool::new(true),
    };
    let recovery = runtime(&keyring, &store);
    let application = IdempotentTerminalApplication::default();
    assert_eq!(
        recovery.apply_pending_terminal_outputs(&application),
        Err(RuntimeProviderExecutionError::PersistenceUnavailable)
    );
    assert_eq!(recovery.apply_pending_terminal_outputs(&application), Ok(1));
    assert_eq!(application.calls.load(Ordering::SeqCst), 2);
    assert_eq!(application.committed.lock().unwrap().len(), 1);
    assert!(
        recovery
            .recover_pending_terminal_outputs()
            .unwrap()
            .is_empty()
    );
}
