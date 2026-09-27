const SOURCECRAFT_JOURNAL: &str =
    "{\"sequence\":0,\"kind\":{\"kind\":\"text_delta\",\"text\":\"sourcecraft-journal-event\"}}";
const SOURCECRAFT_JOURNAL_DIGEST: &str =
    "ccdb4af6ac492d2b55d1a4fb21750dc28dc1039c6f4336cdfd0aed9ee4daa4a6";
const SOURCECRAFT_JOURNAL_CIPHER: &str = "6b78da32976c934576e7d02d24c535ac6f652959b688e0ff0c2800c756e38121ee2d4549eaead922598b3b17e907046cc5cf01b0eea2e7a53ef46691dff5ba850b21fbd16cd917500ce11c180fe937894acad72b5c9a840beb72ea3936b9";
const RUNNE_JOURNAL_CIPHER: &str = "6b78da32976c934576e7d02d24c535ac6f652959b688e0ff0c2800c756e38121ee2d4549eaead922598b3b17e907046cc5cf01b0eea2e7a53ef46691dff5ba850b21fbd16cd917500ce11c180fe915909d264f599a508860f22a3ec03add";
const SOURCECRAFT_OUTBOX_CIPHER: &str =
    "8c0825fae40848a3bc3b1869cfabc6fa8906d554eaee323033fae2c23a70ceb8d553dc24eb173a1af0";
const RUNNE_OUTBOX_CIPHER: &str =
    "8c0825fae40848a3bc3b1869cfabc6fa8906d554eaee323033b1fd7e6e8787e2b62dbf8277d434d463";
const OUTBOX_ID: &str = "edef782d29c79023c49ba615729a7f3c";
const OUTBOX_DIGEST: &str = "4b80fde4929616c0d79b41c0499e4942dd17a2c0d8bf4cfa9ace1b053c360f27";

struct SourcecraftVectorDatabase {
    database: validated_reopen::ValidatedTestDatabase,
    identity: validated_reopen::MainDatabaseIdentity,
    store: SqliteProviderExecutionStore,
}

impl SourcecraftVectorDatabase {
    fn seed(journal_cipher: &str, outbox_cipher: &str) -> Self {
        let database = validated_reopen::ValidatedTestDatabase::new("sourcecraft-provider-reopen");
        let identity = validated_reopen::initialize_database_identity(database.path()).unwrap();
        let connection =
            validated_reopen::open_validated_connection(database.path(), identity).unwrap();
        let sql = format!(
            "INSERT INTO provider_prepared_requests VALUES (X'{call}', X'{prepared}', X'{render}', X'{profile}', X'{record}', 2);
             INSERT INTO provider_dispatch_attempts VALUES (X'{attempt}', X'{call}', X'{permit}', X'{tokens}', X'{cost}', 6, 'sourcecraft-provider-reopen', X'{prepared}', X'{render}', X'{profile}', 4, X'{stream}', X'{settlement}', NULL);
             INSERT INTO provider_effect_authorities VALUES (X'{authority}', 1, X'{attempt}', X'{permit}', 'sourcecraft-grant', X'{tokens}', X'{cost}', X'{prepared}', X'{render}', X'{profile}', 'sourcecraft-owner', 'provider.dispatch', 6, 9999999999, 0, 1, 'sourcecraft:05');
             INSERT INTO provider_execution_admissions (provider_idempotency_key, semantic_digest, principal_id, conversation_id, taskrun_id, execution_attempt_id, call_id, dispatch_attempt_id, authority_id, authority_revision, permit_id, token_reservation_id, cost_reservation_id, runtime_authority_id, database_generation, generation, fencing_token, prepared_digest, render_digest, profile_digest, pricing_revision_digest, requested_input_tokens, requested_output_tokens, max_cost_micros, currency, issued_at, expires_at) VALUES ('sourcecraft-provider-reopen', X'{semantic}', 'sourcecraft-principal', X'{conversation}', X'{taskrun}', X'{execution}', X'{call}', X'{attempt}', X'{authority}', 1, X'{permit}', X'{tokens}', X'{cost}', X'{runtime_authority}', 3, 8, 6, X'{prepared}', X'{render}', X'{profile}', X'{pricing}', 500, 900, 50000, 'USD', 1, 9999999999);
             INSERT INTO provider_journal_key_refs VALUES (X'{key}', 1, X'{runtime_authority}', 3, 1, 1, 1, NULL);
             INSERT INTO provider_encryption_nonces VALUES (X'{key}', 1, X'{journal_nonce}', 1, X'{attempt}', 0);
             INSERT INTO provider_encryption_nonces VALUES (X'{key}', 1, X'{outbox_nonce}', 2, X'{attempt}', NULL);
             INSERT INTO provider_stream_journal VALUES (X'{attempt}', 0, X'{key}', 1, X'{journal_nonce}', 2, X'{profile}', 8, 2, 0, X'{journal_cipher}', 78, X'{journal_digest}');
             INSERT INTO provider_terminal_outbox VALUES (X'{outbox_id}', X'{attempt}', 9, 2, X'{key}', 1, X'{outbox_nonce}', 8, X'{profile}', X'{outbox_cipher}', 25, X'{outbox_digest}', X'{settlement}', 'sourcecraft-terminal', 1, NULL, 1, NULL);",
            call = "0a".repeat(16), prepared = "0b".repeat(32), render = "0c".repeat(32),
            profile = "07".repeat(32), record = "0d".repeat(32), attempt = "05".repeat(16),
            permit = "0e".repeat(16), tokens = "0f".repeat(16), cost = "10".repeat(16),
            stream = "11".repeat(16), settlement = "62".repeat(32), authority = "12".repeat(16),
            semantic = "13".repeat(32), conversation = "14".repeat(16), taskrun = "15".repeat(16),
            execution = "16".repeat(16), runtime_authority = "02".repeat(16), pricing = "03".repeat(32),
            key = "01".repeat(16), journal_nonce = "08".repeat(12), outbox_nonce = "09".repeat(12),
            journal_cipher = journal_cipher, journal_digest = SOURCECRAFT_JOURNAL_DIGEST,
            outbox_id = OUTBOX_ID, outbox_cipher = outbox_cipher, outbox_digest = OUTBOX_DIGEST,
        );
        connection.execute_batch(&sql).unwrap();
        drop(connection);
        let store = validated_reopen::open_provider_execution(database.path(), identity).unwrap();
        Self {
            database,
            identity,
            store,
        }
    }

    fn runtime<'a>(
        &'a self,
        keyring: &'a MemoryKeyring,
    ) -> RuntimeProviderExecution<'a, MemoryKeyring, SqliteProviderExecutionStore, FixedPricing>
    {
        let key = ProviderJournalKeyMaterial::new(
            ProviderJournalKeyRef::new([1; 16], 1, [2; 16], 3).unwrap(),
            [4; 32],
        )
        .unwrap();
        keyring.store_provider_journal_key(&key).unwrap();
        runtime(keyring, &self.store)
    }

    fn snapshot(&self) -> SqlSnapshot {
        let connection =
            validated_reopen::open_validated_reader(self.database.path(), self.identity).unwrap();
        sql_snapshot(&connection)
    }
}

#[test]
fn sourcecraft_journal_reopens_without_rewrite() {
    let database =
        SourcecraftVectorDatabase::seed(SOURCECRAFT_JOURNAL_CIPHER, SOURCECRAFT_OUTBOX_CIPHER);
    let keyring = MemoryKeyring::default();
    let before = database.snapshot();
    let events = database
        .runtime(&keyring)
        .recover_events(runne_provider::DispatchAttemptId::from_bytes([5; 16]))
        .unwrap();
    assert_eq!(
        events,
        vec![
            ProviderStreamEvent::new(
                0,
                ProviderStreamEventKind::TextDelta {
                    text: "sourcecraft-journal-event".to_owned()
                }
            )
            .unwrap()
        ]
    );
    assert_eq!(
        serde_json::to_string(&events[0]).unwrap(),
        SOURCECRAFT_JOURNAL
    );
    assert_eq!(database.snapshot(), before);
}

#[test]
fn runne_journal_alias_is_rejected_without_rewrite() {
    let database = SourcecraftVectorDatabase::seed(RUNNE_JOURNAL_CIPHER, SOURCECRAFT_OUTBOX_CIPHER);
    let keyring = MemoryKeyring::default();
    let before = database.snapshot();
    assert_eq!(
        database
            .runtime(&keyring)
            .recover_events(runne_provider::DispatchAttemptId::from_bytes([5; 16])),
        Err(RuntimeProviderExecutionError::JournalCorrupt)
    );
    assert_eq!(database.snapshot(), before);
}

#[test]
fn sourcecraft_outbox_reopens_without_rewrite() {
    let database =
        SourcecraftVectorDatabase::seed(SOURCECRAFT_JOURNAL_CIPHER, SOURCECRAFT_OUTBOX_CIPHER);
    let keyring = MemoryKeyring::default();
    let before = database.snapshot();
    let recovered = database
        .runtime(&keyring)
        .recover_pending_terminal_outputs()
        .unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].output(), b"sourcecraft-outbox-output");
    assert_eq!(hex::encode(recovered[0].record().outbox_id), OUTBOX_ID);
    assert_eq!(database.snapshot(), before);
}

#[test]
fn runne_outbox_alias_is_rejected_without_rewrite() {
    let database = SourcecraftVectorDatabase::seed(SOURCECRAFT_JOURNAL_CIPHER, RUNNE_OUTBOX_CIPHER);
    let keyring = MemoryKeyring::default();
    let before = database.snapshot();
    assert!(matches!(
        database
            .runtime(&keyring)
            .recover_pending_terminal_outputs(),
        Err(RuntimeProviderExecutionError::JournalCorrupt)
    ));
    assert_eq!(database.snapshot(), before);
}
#[test]
fn redaction_failure_observer_distinguishes_checkpoint_persist_and_advance() {
    #[derive(Clone, Copy)]
    enum FailAt {
        Persist,
        Advance,
    }
    struct FailingPersistence {
        inner: SqliteProviderRecoveryStore,
        fail_at: FailAt,
    }
    impl ScannerRecoveryPersistence for FailingPersistence {
        fn persist_checkpoint(
            &self,
            checkpoint: runne_provider::ScannerCheckpoint,
        ) -> Result<(), runne_runtime::provider_redaction::ScannerRecoveryPersistenceError> {
            if matches!(self.fail_at, FailAt::Persist) {
                return Err(
                    runne_runtime::provider_redaction::ScannerRecoveryPersistenceError::Unavailable,
                );
            }
            self.inner.persist_checkpoint(checkpoint)
        }

        fn advance_checkpoint(
            &self,
            checkpoint: runne_provider::ScannerCheckpoint,
        ) -> Result<(), runne_runtime::provider_redaction::ScannerRecoveryPersistenceError> {
            if matches!(self.fail_at, FailAt::Advance) {
                return Err(
                    runne_runtime::provider_redaction::ScannerRecoveryPersistenceError::Conflict,
                );
            }
            self.inner.advance_checkpoint(checkpoint)
        }

        fn advance_final_checkpoint(
            &self,
            checkpoint: runne_provider::ScannerCheckpoint,
        ) -> Result<(), runne_runtime::provider_redaction::ScannerRecoveryPersistenceError> {
            self.inner.advance_final_checkpoint(checkpoint)
        }

        fn commit_terminal(
            &self,
            binding: TailBinding,
            disposition: ScannerTerminalDisposition,
        ) -> Result<
            ScannerTerminalDisposition,
            runne_runtime::provider_redaction::ScannerRecoveryPersistenceError,
        > {
            self.inner.commit_terminal(binding, disposition)
        }

        fn terminalize_corrupt_checkpoint(
            &self,
            binding: TailBinding,
        ) -> Result<
            ScannerTerminalDisposition,
            runne_runtime::provider_redaction::ScannerRecoveryPersistenceError,
        > {
            self.inner.terminalize_corrupt_checkpoint(binding)
        }

        fn load(
            &self,
            attempt_id: runne_provider::DispatchAttemptId,
        ) -> Result<
            Option<runne_runtime::provider_redaction::ScannerRecoveryRecord>,
            runne_runtime::provider_redaction::ScannerRecoveryPersistenceError,
        > {
            self.inner.load(attempt_id)
        }
    }
    #[derive(Default)]
    struct Observer(Mutex<Vec<(RedactionFailureSite, RedactionFailureKind)>>);
    impl ProviderRedactionObserver for Observer {
        fn observe_failure(&self, site: RedactionFailureSite, kind: RedactionFailureKind) {
            self.0.lock().unwrap().push((site, kind));
        }
    }

    for (fail_at, expected_site, expected_kind) in [
        (
            FailAt::Persist,
            RedactionFailureSite::IngestCheckpointPersist,
            RedactionFailureKind::RecoveryUnavailable,
        ),
        (
            FailAt::Advance,
            RedactionFailureSite::IngestCheckpointAdvance,
            RedactionFailureKind::RecoveryConflict,
        ),
    ] {
        let fixture = fixture();
        let persistence = FailingPersistence {
            inner: SqliteProviderRecoveryStore::open(&fixture.path, [1; 16]).unwrap(),
            fail_at,
        };
        let tails = ExecutionTailStore::default();
        let observer = Observer::default();
        let boundary = ProviderEventRedactionBoundary::new(&tails, &persistence, &ExecutionMatcher)
            .with_observer(&observer);
        let event = ProviderStreamEvent::new(
            0,
            ProviderStreamEventKind::TextDelta {
                text: "checkpoint".into(),
            },
        )
        .unwrap();

        assert!(matches!(
            boundary.scan_before_journal(&context(&fixture), &event),
            Err(ProviderRedactionError::PersistenceUnavailable)
        ));
        assert_eq!(
            observer.0.lock().unwrap().as_slice(),
            &[(expected_site, expected_kind)]
        );
        assert_eq!(
            persistence
                .load(fixture.attempt_id)
                .unwrap()
                .unwrap()
                .disposition(),
            Some(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::CheckpointSecretStateUnavailable
            ))
        );
    }
}
