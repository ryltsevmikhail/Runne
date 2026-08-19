include!("provider_redaction_recovery/support.rs");

#[test]
fn sse_split_matrix_withholds_every_cross_boundary_match() {
    let bytes = b"prefix credential-token suffix";
    for split in 0..=bytes.len() {
        let (directory, durable) = stores();
        let tails = MemoryTailStore::default();
        let matcher = FixtureMatcher {
            epoch: 13,
            unavailable: false,
            scanner_unavailable: false,
        };
        let mut staged = Zeroizing::new(Vec::new());
        let mut recovery =
            ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();
        recovery.ingest(&bytes[..split], &mut staged).unwrap();
        recovery.ingest(&bytes[split..], &mut staged).unwrap();

        assert!(!staged.windows(SECRET.len()).any(|window| window == SECRET));
        assert_eq!(
            recovery.disposition(),
            Some(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::SecretDetected,
            ))
        );
        assert_no_publication(&durable);
        drop(durable);
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            if let Ok(durable_bytes) = std::fs::read(entry.unwrap().path()) {
                assert!(
                    !durable_bytes
                        .windows(SECRET.len())
                        .any(|window| window == SECRET)
                );
            }
        }
    }
}

#[test]
fn tail_crash_restart_requires_matching_native_ref() {
    let (_directory, durable) = stores();
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
    let reference = first.checkpoint().unwrap().tail_reference();

    let mut restarted =
        ProviderRedactionRecovery::restart(binding(), &tails, &durable, &matcher).unwrap();
    restarted
        .ingest(b"ential-token suffix", &mut staged)
        .unwrap();
    assert_eq!(
        restarted.disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::SecretDetected,
        ))
    );
    assert!(!staged.windows(SECRET.len()).any(|window| window == SECRET));
    tails.remove(reference);

    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let mut first =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();
    first.ingest(b"prefix cred", &mut staged).unwrap();
    let mismatched = TailBinding::new(binding().attempt_id(), 10, 11, 13, 1, 0).unwrap();
    let restarted =
        ProviderRedactionRecovery::restart(mismatched, &tails, &durable, &matcher).unwrap();
    assert_eq!(
        restarted.disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ))
    );
    assert_no_publication(&durable);
}

#[test]
fn corrupt_ref_or_checkpoint_is_checkpoint_secret_state_unavailable() {
    for mode in 0..3 {
        let (_directory, durable) = stores();
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
        let reference = first.checkpoint().unwrap().tail_reference();
        match mode {
            0 => tails.remove(reference),
            1 => tails.corrupt(reference),
            _ => tails.make_unavailable(),
        }

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
            "UPDATE provider_scanner_recovery SET checkpoint_digest=zeroblob(32)",
            [],
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
    let replayed =
        ProviderRedactionRecovery::restart(binding(), &tails, &durable, &matcher).unwrap();
    assert_eq!(replayed.disposition(), restarted.disposition());
    assert_no_publication(&durable);
}

#[test]
fn matcher_epoch_rollback_is_terminal() {
    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let current = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };
    let mut staged = Zeroizing::new(Vec::new());
    let mut first =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &current).unwrap();
    first.ingest(b"prefix cred", &mut staged).unwrap();

    let rollback = FixtureMatcher {
        epoch: 12,
        unavailable: false,
        scanner_unavailable: false,
    };
    let restarted =
        ProviderRedactionRecovery::restart(binding(), &tails, &durable, &rollback).unwrap();
    assert_eq!(
        restarted.disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CredentialMatcherUnavailable,
        ))
    );
    assert_no_publication(&durable);
}

#[test]
fn policy_error_has_no_canonical_replay_or_outbox() {
    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: true,
    };
    let mut result =
        ProviderRedactionRecovery::start(binding(), &tails, &durable, &matcher).unwrap();
    let mut staged = Zeroizing::new(Vec::new());
    result.ingest(b"provider output", &mut staged).unwrap();
    assert_eq!(
        result.disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::RedactionScannerUnavailable,
        ))
    );
    assert_no_publication(&durable);
}

#[test]
fn terminal_lattice_never_downgrades_scanner_failure() {
    let (_directory, durable) = stores();
    let binding = binding();
    durable
        .commit_terminal(
            binding,
            ScannerTerminalDisposition::Uncertain(ScannerUncertainReason::SecretDetected),
        )
        .unwrap();
    durable
        .commit_terminal(binding, ScannerTerminalDisposition::Completed)
        .unwrap();
    assert_eq!(
        durable
            .load(binding.attempt_id())
            .unwrap()
            .unwrap()
            .disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::SecretDetected,
        ))
    );
    assert_no_publication(&durable);
}

#[test]
fn four_durable_boundaries_require_checkpoint_before_cursor_and_terminal() {
    let matcher = FixtureMatcher {
        epoch: 13,
        unavailable: false,
        scanner_unavailable: false,
    };

    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let absent = ProviderRedactionRecovery::restart(binding(), &tails, &durable, &matcher).unwrap();
    assert_eq!(
        absent.disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ))
    );

    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let advanced_binding = TailBinding::new(binding().attempt_id(), 9, 11, 13, 1, 4).unwrap();
    let reference = tails
        .put_tail(advanced_binding, Zeroizing::new(b"tail".to_vec()))
        .unwrap();
    let checkpoint =
        runne_provider::ScannerCheckpoint::new(reference, advanced_binding, 1, 0).unwrap();
    durable.persist_checkpoint(checkpoint).unwrap();
    let torn = ProviderRedactionRecovery::restart(binding(), &tails, &durable, &matcher).unwrap();
    assert_eq!(
        torn.disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ))
    );

    let (_directory, durable) = stores();
    let tails = MemoryTailStore::default();
    let reference = tails
        .put_tail(advanced_binding, Zeroizing::new(b"tail".to_vec()))
        .unwrap();
    let checkpoint =
        runne_provider::ScannerCheckpoint::new(reference, advanced_binding, 1, 0).unwrap();
    durable.persist_checkpoint(checkpoint).unwrap();
    durable.advance_checkpoint(checkpoint).unwrap();
    let resumable =
        ProviderRedactionRecovery::restart(binding(), &tails, &durable, &matcher).unwrap();
    assert_eq!(resumable.disposition(), None);
}

include!("provider_redaction_recovery/completion.rs");
include!("provider_redaction_recovery/terminal_authority.rs");
