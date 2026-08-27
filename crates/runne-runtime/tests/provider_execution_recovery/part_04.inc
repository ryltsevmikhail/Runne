
#[tokio::test(flavor = "current_thread")]
async fn provider_bytes_without_local_commit_freeze_attempt_as_uncertain() {
    let fixture = fixture();
    let keyring = fixture.keyring();
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
    let connection = validated_connection(&fixture);
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
        attempt_id: runne_provider::DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        self.inner.load_encrypted_events(attempt_id)
    }

    fn load_terminal_pricing_binding(
        &self,
        attempt_id: runne_provider::DispatchAttemptId,
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
        _attempt_id: runne_provider::DispatchAttemptId,
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
    let keyring = fixture.keyring();
    let failing = FailAppendAndFreezeStore {
        inner: Arc::clone(&fixture.execution),
    };
    let binding = runtime(&keyring, fixture.execution.as_ref())
        .preflight_existing_active_key([1; 16], 7)
        .unwrap();
    let writer = runtime(&keyring, &failing);
    writer.use_existing_active_key(binding).unwrap();
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
    let connection = validated_connection(&fixture);
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
    let connection = validated_connection(&fixture);
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

pub(crate) struct FailFirstAcknowledgementStore {
    pub(crate) inner: Arc<SqliteProviderExecutionStore>,
    pub(crate) fail_acknowledgement: AtomicBool,
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
        attempt_id: runne_provider::DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        self.inner.load_encrypted_events(attempt_id)
    }

    fn load_terminal_pricing_binding(
        &self,
        attempt_id: runne_provider::DispatchAttemptId,
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
        attempt_id: runne_provider::DispatchAttemptId,
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
