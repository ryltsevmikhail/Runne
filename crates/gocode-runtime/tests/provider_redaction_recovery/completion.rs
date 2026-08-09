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
