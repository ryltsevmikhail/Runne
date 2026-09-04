use super::*;
use crate::provider::credential_lifecycle::online_test_support::revoke;
mod authority_revision;
mod poll_expiry;

#[test]
fn prepared_revoke_fences_cached_binding_and_new_dispatch_before_native_delete() {
    verify_revoke(false, false, false);
}

#[test]
fn started_effect_binding_revalidates_until_revoke_without_reading_secret() {
    verify_revoke(true, false, false);
}

#[test]
fn published_stream_replay_is_fenced_after_revoke() {
    verify_revoke(true, true, false);
}

#[test]
fn publication_samples_clock_after_waiting_for_sqlite_writer() {
    verify_revoke(true, false, true);
}

fn verify_revoke(started: bool, published: bool, delayed: bool) {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "prepared-revoke.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 82, "before-revoke");
    drop(lifecycle);
    let store = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 100)).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::super::authority_test_support::prepare_request_for_provider(
                &launch, &path, 82, "openai",
            ),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let lifecycle = reopen_test_store(&path, 100);
    let (credential, cached) = lifecycle
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap()
        .split();
    if started {
        store
            .start_online_effect(&launch, admission.claim(), &cached)
            .unwrap();
    }
    credential
        .validate_online_materialization(
            crate::provider::CredentialDispatchAuthority::new(&lifecycle, &launch),
            admission.claim(),
            100,
        )
        .unwrap();
    let dispatch = crate::provider::SqliteProviderDispatchStore::open_with_connection(
        path.to_str().unwrap(),
        super::super::authority_test_support::configured_connection(&path),
    )
    .unwrap();
    let publication = crate::provider::MarkProviderStreaming {
        attempt_id: admission.claim().attempt_id,
        fencing_token: admission.claim().fencing_token,
        stream_id: runne_provider::ProviderStreamId::from_bytes([9; 16]),
    };
    if delayed {
        verify_delayed_publication(&path, &dispatch, &publication);
    }
    if published {
        assert!(matches!(
            dispatch.mark_streaming(&publication),
            Err(crate::provider::ProviderStoreError::StaleFencingToken),
        ));
        assert_eq!(
            dispatch
                .mark_streaming_online(&publication, || 100)
                .unwrap(),
            crate::provider::ProviderDispatchState::Streaming,
        );
        use runne_application::provider::{ProviderExecutionStore, ProviderPollRequest};
        store
            .begin_provider_poll(&ProviderPollRequest {
                attempt_id: admission.claim().attempt_id,
                fencing_token: admission.claim().fencing_token,
                cursor: 0,
                profile_digest: admission.claim().profile_digest,
                runtime_generation: 11,
            })
            .unwrap();
    }
    let command = revoke(83, "fence-before-delete", 2, 2);
    let operation = command.operation_id();
    ProviderCredentialEnrollmentStore::begin(&lifecycle, command).unwrap();
    drop(lifecycle);
    let reopened = reopen_test_store(&path, 101);
    assert_eq!(
        reopened.load_operation(operation).unwrap().state(),
        runne_provider::CredentialOperationState::Prepared,
    );
    assert!(
        reopened
            .authorize_online_dispatch(&launch, admission.claim(), 101)
            .is_err()
    );
    assert!(
        credential
            .validate_online_materialization(
                crate::provider::CredentialDispatchAuthority::new(&reopened, &launch),
                admission.claim(),
                101,
            )
            .is_err()
    );
    if !started {
        assert!(matches!(
            store.start_online_effect(&launch, admission.claim(), &cached),
            Err(ProviderAdmissionError::AuthorityDenied),
        ));
    }
    assert_eq!(counts(&path), if started { (1, 1, 1) } else { (0, 0, 0) });
    if published {
        use runne_application::provider::{ProviderExecutionStore, ProviderPollRequest};
        assert_eq!(
            store.begin_provider_poll(&ProviderPollRequest {
                attempt_id: admission.claim().attempt_id,
                fencing_token: admission.claim().fencing_token,
                cursor: 0,
                profile_digest: admission.claim().profile_digest,
                runtime_generation: 11,
            }),
            Err(runne_application::provider::ProviderExecutionError::StaleGeneration),
        );
        let flights: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM provider_poll_flights", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(flights, 1);
        verify_revoked_append(&store, admission.claim());
    }
    if started {
        assert!(matches!(
            dispatch.mark_streaming_online(&publication, || 101),
            Err(crate::provider::ProviderStoreError::StaleFencingToken),
        ));
    }
}

fn verify_revoked_append(
    store: &SqliteProviderExecutionStore,
    claim: &runne_provider::ProviderDispatchClaim,
) {
    use runne_application::provider::{
        ProviderEncryptedPayload, ProviderExecutionError, ProviderExecutionStore,
        ProviderJournalAppendRequest, ProviderJournalKeyBinding,
    };
    let request = ProviderJournalAppendRequest {
        attempt_id: claim.attempt_id,
        fencing_token: claim.fencing_token,
        sequence: 0,
        event_kind: 1,
        terminal: false,
        call_digest_version: runne_provider::ProviderCallDigestVersion::V2,
        profile_digest: claim.profile_digest,
        runtime_generation: 11,
        key: ProviderJournalKeyBinding::new([9; 16], 1, [1; 16], 7).unwrap(),
        encrypted: ProviderEncryptedPayload::new([81; 12], vec![82; 32], 16, [83; 32]).unwrap(),
    };
    assert_eq!(
        store.append_encrypted_event(&request),
        Err(ProviderExecutionError::StaleGeneration)
    );
    assert!(
        store
            .load_encrypted_events(claim.attempt_id)
            .unwrap()
            .is_empty()
    );
}

fn verify_delayed_publication(
    path: &std::path::Path,
    dispatch: &crate::provider::SqliteProviderDispatchStore,
    publication: &crate::provider::MarkProviderStreaming,
) {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::Duration;
    let blocker = Connection::open(path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let now = AtomicI64::new(219);
    let (sampled, observed) = std::sync::mpsc::channel();
    let (early, result) = std::thread::scope(|scope| {
        let pending = scope.spawn(|| {
            dispatch.mark_streaming_online(publication, || {
                let value = now.load(Ordering::SeqCst);
                sampled.send(value).unwrap();
                value
            })
        });
        let early = observed.recv_timeout(Duration::from_millis(200)).ok();
        now.store(220, Ordering::SeqCst);
        blocker.execute_batch("COMMIT").unwrap();
        (early, pending.join().unwrap())
    });
    assert_eq!(early, None, "clock sampled while publication was blocked");
    assert_eq!(observed.recv().unwrap(), 220);
    assert_eq!(
        result,
        Err(crate::provider::ProviderStoreError::StaleFencingToken)
    );
}
