#[path = "task5_support.rs"]
mod task5_support;

#[tokio::test(flavor = "current_thread")]
async fn terminal_scanner_failure_has_no_publication() {
    use gocode_provider::{
        DispatchAttemptId, ProviderCallDigestVersion, ProviderStreamId, ScannerTerminalDisposition,
        ScannerUncertainReason, StreamCursor,
    };
    use gocode_runtime::provider_execution::{
        ProviderEventJournalContext, RuntimeProviderExecution, RuntimeProviderExecutionError,
    };
    use gocode_runtime::provider_redaction::{
        ProviderEventRedactionBoundary, ScannerRecoveryPersistence,
    };
    use gocode_store::provider::SqliteProviderRecoveryStore;

    use task5_support::*;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite");
    drop(gocode_store::provider::SqliteProviderDispatchStore::open(&path).unwrap());
    let recovery = SqliteProviderRecoveryStore::open(&path).unwrap();
    let tails = SecretTailStore::default();
    let matcher = SecretMatcher;
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &matcher);
    let store = PublicationCountingStore::default();
    let keyring = gocode_secure_store::StubStore::new();
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        &store,
        &FixedPricing,
        &AllowingGuard,
        &redaction,
    );
    let attempt = DispatchAttemptId::from_bytes([5; 16]);
    let context = ProviderEventJournalContext {
        attempt_id: attempt,
        fencing_token: 9,
        call_digest_version: ProviderCallDigestVersion::V2,
        profile_digest: [4; 32],
        runtime_generation: 11,
    };
    let provider = SecretProvider;

    for _retry in 0..2 {
        assert_eq!(
            runtime
                .next_and_commit(
                    &provider,
                    &ProviderStreamId::from_bytes([7; 16]),
                    StreamCursor::new(0),
                    &context,
                )
                .await,
            Err(RuntimeProviderExecutionError::PolicyDenied)
        );
    }

    let disposition = recovery.load(attempt).unwrap().unwrap().disposition();
    assert_eq!(
        disposition,
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::SecretDetected,
        ))
    );
    assert_eq!(
        runtime.finalize_terminal_output(&context),
        Err(RuntimeProviderExecutionError::PolicyDenied)
    );
    assert_eq!(store.polls(), 2, "the exact retry was durably armed twice");
    assert_eq!(store.journal_appends(), 0, "secret bytes reached the journal");
    assert_eq!(store.outbox_commits(), 0, "a terminal outbox was attempted");
    assert_eq!(store.uncertain_audits(), 2, "retry audit evidence was lost");
    assert_eq!(recovery.canonical_publication_counts().unwrap(), (0, 0));
    assert_eq!(tails.tail_count(), 0, "terminal scanning leaked a native tail");

    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap_or_default();
        assert!(!bytes.windows(SECRET.len()).any(|window| window == SECRET));
    }
}
