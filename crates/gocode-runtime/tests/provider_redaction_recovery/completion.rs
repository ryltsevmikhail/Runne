#[test]
fn completed_scan_flushes_tail_before_success_without_automatic_publication() {
    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };
    let mut staged = Zeroizing::new(Vec::new());
    let mut recovery =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();
    recovery.ingest(b"harmless provider output", &mut staged).unwrap();
    recovery.complete(&mut staged).unwrap();
    assert_eq!(&*staged, b"harmless provider output");
    assert_eq!(recovery.disposition(), Some(ScannerTerminalDisposition::Completed));
    assert_no_publication(&durable);
}

#[test]
fn provider_echo_replay_is_terminal_without_duplicate_publication() {
    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };
    let mut staged = Zeroizing::new(Vec::new());
    let mut recovery =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();
    recovery.ingest_at(0, b"clean provider output", &mut staged).unwrap();
    recovery.ingest_at(0, b"clean provider output", &mut staged).unwrap();
    assert_eq!(recovery.disposition(), Some(ScannerTerminalDisposition::Uncertain(
        ScannerUncertainReason::CheckpointSecretStateUnavailable,
    )));
    assert_no_publication(&durable);
}

#[test]
fn superseded_and_terminal_native_tails_are_deleted_in_order() {
    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };
    let mut staged = Zeroizing::new(Vec::new());
    let mut recovery =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();

    recovery.ingest(b"first harmless chunk", &mut staged).unwrap();
    assert_eq!(tails.tail_count(), 1);
    recovery.ingest(b" second harmless chunk", &mut staged).unwrap();
    assert_eq!(tails.tail_count(), 1, "the superseded reference leaked");
    recovery.complete(&mut staged).unwrap();
    assert_eq!(tails.tail_count(), 0, "terminal references leaked");
}

#[test]
fn restart_purges_attempt_orphans_but_retains_the_durable_reference() {
    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };
    let mut staged = Zeroizing::new(Vec::new());
    let mut recovery =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();
    recovery.ingest(b"durable clean chunk", &mut staged).unwrap();
    let retained = recovery.checkpoint().unwrap().tail_reference();
    let orphan_binding = TailBinding::new(binding().attempt_id(), 9, 11, 13, 1, 99).unwrap();
    let orphan = tails
        .put_tail(orphan_binding, Zeroizing::new(b"orphan".to_vec()))
        .unwrap();
    assert_eq!(tails.tail_count(), 2);

    let restarted =
        ProviderRedactionRecovery::restart(binding(), &tails, &durable, &matcher).unwrap();
    assert_eq!(restarted.disposition(), None);
    assert_eq!(tails.tail_count(), 1);
    assert!(tails.load_tail(&retained, restarted.checkpoint().unwrap().binding()).is_ok());
    assert_eq!(
        tails.load_tail(&orphan, orphan_binding),
        Err(SecureStoreError::NotFound)
    );
}

#[test]
fn new_session_purges_pre_checkpoint_crash_orphans() {
    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };
    let orphan_binding = TailBinding::new(binding().attempt_id(), 9, 11, 13, 1, 33).unwrap();
    tails
        .put_tail(orphan_binding, Zeroizing::new(b"orphan".to_vec()))
        .unwrap();
    assert_eq!(tails.tail_count(), 1);

    let recovery =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();
    assert_eq!(recovery.disposition(), None);
    assert_eq!(tails.tail_count(), 0);
}

#[test]
fn native_tail_delete_is_idempotent() {
    let tails = MemoryTailStore::default();
    let reference = tails
        .put_tail(binding(), Zeroizing::new(b"ephemeral".to_vec()))
        .unwrap();
    tails.delete_tail(&reference).unwrap();
    tails.delete_tail(&reference).unwrap();
    assert_eq!(tails.tail_count(), 0);
}

#[test]
fn checkpoint_failures_never_release_staged_bytes_or_native_orphans() {
    for phase in [FailPhase::Persist, FailPhase::Advance] {
        let (_directory, durable) = stores();
        let failing = FailingPersistence {
            inner: &durable,
            phase,
        };
        let tails = MemoryTailStore::default();
        let matcher = FixtureMatcher {
            epoch: 13,
            unavailable: false,
            scanner_unavailable: false,
        };
        let mut staged = Zeroizing::new(b"already-private".to_vec());
        let before = staged.clone();
        let mut recovery =
            ProviderRedactionRecovery::start(binding(), &tails, &failing, &matcher).unwrap();
        assert_eq!(
            recovery.ingest(b"a harmless chunk long enough", &mut staged),
            Err(ProviderRedactionError::PersistenceUnavailable)
        );
        assert_eq!(staged, before);
        assert_eq!(
            recovery.disposition(),
            Some(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::CheckpointSecretStateUnavailable,
            ))
        );
        assert_eq!(tails.tail_count(), 0);
        assert_no_publication(&durable);
    }
}
#[test]
fn durable_checkpoint_digest_mismatch_is_checkpoint_secret_state_unavailable() {
    let (directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };
    let mut staged = Zeroizing::new(Vec::new());
    let mut first =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();
    first.ingest(b"prefix cred", &mut staged).unwrap();
    let connection =
        rusqlite::Connection::open(directory.path().join("provider.sqlite.scanner-recovery"))
            .unwrap();
    connection
        .execute(
            "UPDATE provider_scanner_recovery SET durable_checkpoint_digest=?1",
            [[91_u8; 32]],
        )
        .unwrap();
    drop(connection);

    let restarted =
        ProviderRedactionRecovery::restart(binding(), &tails, &durable, &matcher).unwrap();
    assert_eq!(
        restarted.disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ))
    );
    assert_no_publication(&durable);
}

struct StrongerTerminalRace<'a> {
    inner: &'a SqliteProviderRecoveryStore,
    raced: std::sync::atomic::AtomicBool,
}

impl ScannerRecoveryPersistence for StrongerTerminalRace<'_> {
    fn persist_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError> {
        self.inner.persist_checkpoint(checkpoint)
    }

    fn advance_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError> {
        self.inner.advance_checkpoint(checkpoint)
    }

    fn advance_final_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError> {
        self.inner.advance_final_checkpoint(checkpoint)
    }

    fn commit_terminal(
        &self,
        binding: TailBinding,
        disposition: ScannerTerminalDisposition,
    ) -> Result<ScannerTerminalDisposition, ScannerRecoveryPersistenceError> {
        if disposition == ScannerTerminalDisposition::Completed
            && !self.raced.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.inner.commit_terminal(
                binding,
                ScannerTerminalDisposition::Uncertain(
                    ScannerUncertainReason::SecretDetected,
                ),
            )?;
        }
        self.inner.commit_terminal(binding, disposition)
    }

    fn load(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<Option<ScannerRecoveryRecord>, ScannerRecoveryPersistenceError> {
        self.inner.load(attempt)
    }
}

#[test]
fn stronger_concurrent_terminal_blocks_final_tail_release() {
    let (_directory, durable) = stores();
    let racing = StrongerTerminalRace {
        inner: &durable,
        raced: std::sync::atomic::AtomicBool::new(false),
    };
    let tails = MemoryTailStore::default();
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };
    let mut staged = Zeroizing::new(Vec::new());
    let mut recovery =
        ProviderRedactionRecovery::start(binding(), &tails, &racing, &matcher).unwrap();
    recovery.ingest(b"short", &mut staged).unwrap();
    let before_completion = staged.clone();

    recovery.complete(&mut staged).unwrap();

    assert_eq!(staged, before_completion);
    assert_eq!(
        recovery.disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::SecretDetected,
        ))
    );
    assert_eq!(
        durable.load(binding().attempt_id()).unwrap().unwrap().disposition(),
        recovery.disposition()
    );
}
