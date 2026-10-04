use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

struct PausedAppendStore {
    inner: Arc<SqliteProviderExecutionStore>,
    attempts: Mutex<Vec<ProviderJournalAppendRequest>>,
    pause: Mutex<Option<(SyncSender<()>, Receiver<()>)>>,
    unavailable: bool,
}

impl PausedAppendStore {
    fn paused(inner: Arc<SqliteProviderExecutionStore>) -> (Self, Receiver<()>, SyncSender<()>) {
        let (entered_sender, entered) = sync_channel(1);
        let (resume, resume_receiver) = sync_channel(1);
        (
            Self {
                inner,
                attempts: Mutex::new(Vec::new()),
                pause: Mutex::new(Some((entered_sender, resume_receiver))),
                unavailable: false,
            },
            entered,
            resume,
        )
    }

    fn unavailable(inner: Arc<SqliteProviderExecutionStore>) -> Self {
        Self {
            inner,
            attempts: Mutex::new(Vec::new()),
            pause: Mutex::new(None),
            unavailable: true,
        }
    }
}

struct IdempotentTerminalApplication {
    calls: AtomicUsize,
    committed: Mutex<HashMap<String, Vec<u8>>>,
    conversation_id: ConversationId,
    taskrun_id: TaskRunId,
    execution_attempt_id: AttemptId,
}

impl IdempotentTerminalApplication {
    fn for_fixture(fixture: &Fixture) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            committed: Mutex::new(HashMap::new()),
            conversation_id: fixture.conversation_id,
            taskrun_id: fixture.taskrun_id,
            execution_attempt_id: fixture.execution_attempt_id,
        }
    }
}

impl ProviderExecutionStore for PausedAppendStore {
    fn active_journal_key_binding(
        &self,
    ) -> Result<Option<ProviderJournalKeyBinding>, ProviderExecutionError> {
        self.inner.active_journal_key_binding()
    }

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
    fn revalidate_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.revalidate_provider_poll(request)
    }

    fn append_encrypted_event(
        &self,
        request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        self.attempts.lock().unwrap().push(request.clone());
        if self.unavailable {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        if let Some((entered, resume)) = self.pause.lock().unwrap().take() {
            entered.send(()).unwrap();
            resume.recv().unwrap();
        }
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

impl ProviderTerminalPersistence for PausedAppendStore {
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        self.inner.commit_terminal(request)
    }
}

struct SinglePollProvider {
    event: ProviderStreamEvent,
    polls: AtomicUsize,
}

impl ProviderPort for SinglePollProvider {
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
        _cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let event = self.event.clone();
        Box::pin(async move { ProviderStreamItem::from_event(event) })
    }

    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            assert_eq!(request.stream_id(), ProviderStreamId::from_bytes([9; 16]));
            Ok(CancelDisposition::Requested)
        })
    }

    fn reconcile(
        &self,
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("fixture does not reconcile") })
    }
}

#[test]
fn live_stream_rebinds_once_from_retired_k1_to_forward_k2() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let (store, entered, resume) = PausedAppendStore::paused(Arc::clone(&fixture.execution));
    let writer = runtime(&keyring, &store);
    let k1 = writer.preflight_existing_active_key([1; 16], 7).unwrap();
    let event = ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap();
    let provider = SinglePollProvider {
        event: event.clone(),
        polls: AtomicUsize::new(0),
    };
    let stream = ProviderStreamId::from_bytes([9; 16]);

    std::thread::scope(|scope| {
        let append = scope.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(writer.next_and_commit(
                    &provider,
                    &stream,
                    StreamCursor::new(0),
                    &context(&fixture),
                ))
        });
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let k2 = runtime(&keyring, fixture.execution.as_ref())
            .create_and_activate_key([1; 16], 7, 2)
            .unwrap();
        resume.send(()).unwrap();
        assert_eq!(append.join().unwrap().unwrap().event(), &event);
        assert_eq!(
            store
                .attempts
                .lock()
                .unwrap()
                .iter()
                .map(|request| request.key)
                .collect::<Vec<_>>(),
            vec![k1, k2]
        );
        assert_eq!(provider.polls.load(Ordering::SeqCst), 1);
    });

    assert_eq!(writer.recover_events(fixture.attempt_id), Ok(vec![event]));
    let connection = validated_connection(&fixture);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_stream_journal WHERE key_id = ?1 AND sequence = 0",
                [k1.key_id().as_slice()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM provider_encryption_nonces WHERE key_id = ?1 AND dispatch_attempt_id = ?2 AND sequence = 0", [k1.key_id().as_slice(), fixture.attempt_id.as_bytes().as_slice()], |row| row.get::<_, i64>(0)).unwrap(), 0);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_stream_journal WHERE key_version = 2",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM provider_poll_flights", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        3
    );
}
