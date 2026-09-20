fn checkpoint_for(
    tails: &MemoryTailStore,
    binding: TailBinding,
) -> ScannerCheckpoint {
    let reference = tails
        .put_tail(binding, Zeroizing::new(Vec::new()))
        .unwrap();
    ScannerCheckpoint::new(reference, binding, 1, binding.cursor()).unwrap()
}

fn advanced_binding() -> TailBinding {
    TailBinding::new(binding().attempt_id(), 9, 11, 13, 1, 7).unwrap()
}

#[test]
fn ordinary_advanced_checkpoint_cannot_authorize_completed() {
    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let advanced = advanced_binding();
    let checkpoint = checkpoint_for(&tails, advanced);
    durable.persist_checkpoint(checkpoint).unwrap();
    durable.advance_checkpoint(checkpoint).unwrap();
    assert_eq!(
        durable.commit_terminal(advanced, ScannerTerminalDisposition::Completed),
        Err(ScannerRecoveryPersistenceError::Conflict)
    );
}

#[test]
fn completed_rejects_every_same_fence_stale_tail_binding_field() {
    let candidates = [
        TailBinding::new(binding().attempt_id(), 9, 12, 13, 1, 7).unwrap(),
        TailBinding::new(binding().attempt_id(), 9, 11, 14, 1, 7).unwrap(),
        TailBinding::new(binding().attempt_id(), 9, 11, 13, 2, 7).unwrap(),
        TailBinding::new(binding().attempt_id(), 9, 11, 13, 1, 6).unwrap(),
    ];
    for candidate in candidates {
        let (_directory, durable) = stores();
        let tails = MemoryTailStore::default();
        let advanced = advanced_binding();
        let checkpoint = checkpoint_for(&tails, advanced);
        durable.persist_checkpoint(checkpoint).unwrap();
        durable.advance_final_checkpoint(checkpoint).unwrap();
        assert_eq!(
            durable.commit_terminal(candidate, ScannerTerminalDisposition::Completed),
            Err(ScannerRecoveryPersistenceError::Conflict)
        );
    }
}

#[test]
fn every_terminal_candidate_rejects_every_stale_tail_binding_field() {
    let current = advanced_binding();
    let stale_bindings = [
        TailBinding::new(current.attempt_id(), 8, 11, 13, 1, 7).unwrap(),
        TailBinding::new(current.attempt_id(), 9, 12, 13, 1, 7).unwrap(),
        TailBinding::new(current.attempt_id(), 9, 11, 14, 1, 7).unwrap(),
        TailBinding::new(current.attempt_id(), 9, 11, 13, 2, 7).unwrap(),
        TailBinding::new(current.attempt_id(), 9, 11, 13, 1, 6).unwrap(),
    ];
    let terminal_candidates = [
        ScannerTerminalDisposition::Uncertain(ScannerUncertainReason::SecretDetected),
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CredentialMatcherUnavailable,
        ),
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::RedactionScannerUnavailable,
        ),
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ),
        ScannerTerminalDisposition::OutputLimitExceeded,
        ScannerTerminalDisposition::Completed,
    ];
    for stale in stale_bindings {
        for candidate in terminal_candidates {
            let (_directory, durable) = stores();
            let checkpoint = checkpoint_for(&MemoryTailStore::default(), current);
            durable.persist_checkpoint(checkpoint).unwrap();
            assert_eq!(
                durable.commit_terminal(stale, candidate),
                Err(ScannerRecoveryPersistenceError::Conflict)
            );
            assert_eq!(durable.load(current.attempt_id()).unwrap().unwrap().disposition(), None);
        }
    }
}

#[test]
fn corrupt_terminalization_rejects_healthy_rows_and_stale_stable_authority() {
    let (directory, durable) = stores();
    let current = advanced_binding();
    let checkpoint = checkpoint_for(&MemoryTailStore::default(), current);
    durable.persist_checkpoint(checkpoint).unwrap();
    assert_eq!(
        durable.terminalize_corrupt_checkpoint(current),
        Err(ScannerRecoveryPersistenceError::Conflict)
    );
    let database = directory.path().join("runne-daemon").join("provider.sqlite.scanner-recovery");
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE provider_scanner_recovery SET checkpoint_digest=zeroblob(32)",
            [],
        )
        .unwrap();
    let stale = [
        TailBinding::new(DispatchAttemptId::from_bytes([8; 16]), 9, 11, 13, 1, 7).unwrap(),
        TailBinding::new(current.attempt_id(), 8, 11, 13, 1, 7).unwrap(),
        TailBinding::new(current.attempt_id(), 9, 12, 13, 1, 7).unwrap(),
        TailBinding::new(current.attempt_id(), 9, 11, 14, 1, 7).unwrap(),
        TailBinding::new(current.attempt_id(), 9, 11, 13, 2, 7).unwrap(),
    ];
    for candidate in stale {
        assert_eq!(
            durable.terminalize_corrupt_checkpoint(candidate),
            Err(ScannerRecoveryPersistenceError::Conflict)
        );
    }
    let disposition: Option<i64> = rusqlite::Connection::open(database)
        .unwrap()
        .query_row(
            "SELECT disposition FROM provider_scanner_recovery",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(disposition, None);
}

#[test]
fn corrupt_terminalization_is_idempotent_dominant_and_replaces_completed() {
    let (directory, durable) = stores();
    let current = advanced_binding();
    let checkpoint = checkpoint_for(&MemoryTailStore::default(), current);
    durable.persist_checkpoint(checkpoint).unwrap();
    let database = directory.path().join("runne-daemon").join("provider.sqlite.scanner-recovery");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE provider_scanner_recovery
             SET checkpoint_digest=zeroblob(32), disposition=6",
            [],
        )
        .unwrap();
    let checkpoint_uncertain = ScannerTerminalDisposition::Uncertain(
        ScannerUncertainReason::CheckpointSecretStateUnavailable,
    );
    assert_eq!(
        durable.terminalize_corrupt_checkpoint(current),
        Ok(checkpoint_uncertain)
    );
    assert_eq!(
        durable.terminalize_corrupt_checkpoint(current),
        Ok(checkpoint_uncertain)
    );
    connection
        .execute(
            "UPDATE provider_scanner_recovery SET disposition=1",
            [],
        )
        .unwrap();
    assert_eq!(
        durable.terminalize_corrupt_checkpoint(current),
        Ok(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::SecretDetected
        ))
    );
}

#[test]
fn unproven_completed_record_is_corrupt_and_cannot_publish() {
    let (directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let advanced = advanced_binding();
    let checkpoint = checkpoint_for(&tails, advanced);
    durable.persist_checkpoint(checkpoint).unwrap();
    durable.advance_checkpoint(checkpoint).unwrap();

    let connection = rusqlite::Connection::open(
        directory.path().join("runne-daemon").join("provider.sqlite.scanner-recovery"),
    )
    .unwrap();
    connection
        .execute(
            "UPDATE provider_scanner_recovery SET disposition=6 WHERE attempt_id=?1",
            [advanced.attempt_id().as_bytes()],
        )
        .unwrap();
    drop(connection);

    assert_eq!(
        durable.load(advanced.attempt_id()),
        Err(ScannerRecoveryPersistenceError::Corrupt)
    );
}
