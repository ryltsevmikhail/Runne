#[test]
fn terminal_scanner_failure_has_no_publication() {
    use gocode_provider::{
        ScannerTerminalDisposition, ScannerUncertainReason, TailBinding,
    };
    use gocode_runtime::provider_redaction::ScannerRecoveryPersistence;
    use gocode_store::provider::SqliteProviderRecoveryStore;

    let (directory, dispatch, claim) = setup("scanner-terminal-no-publication");
    drop(dispatch);
    let recovery = SqliteProviderRecoveryStore::open(&directory.path().join("s")).unwrap();
    let binding = TailBinding::new(claim.attempt_id, claim.fencing_token, 1, 1, 1, 0).unwrap();
    recovery
        .commit_terminal(
            binding,
            ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::CheckpointSecretStateUnavailable,
            ),
        )
        .unwrap();

    assert_eq!(recovery.canonical_publication_counts().unwrap(), (0, 0));
    assert_eq!(
        recovery.load(claim.attempt_id).unwrap().unwrap().disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ))
    );
}
