use super::*;
use runne_application::provider::{
    ProviderExecutionError, ProviderExecutionStore, ProviderPollRequest,
};
use std::sync::atomic::{AtomicI64, Ordering};

#[test]
fn armed_poll_revalidation_rejects_exact_authority_deadline() {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "poll-expiry.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 84, "poll-expiry");
    drop(lifecycle);
    let clock = Arc::new(AtomicI64::new(100));
    let observed = Arc::clone(&clock);
    let store = SqliteProviderExecutionStore::open_with_now(
        &path,
        Arc::new(move || observed.load(Ordering::SeqCst)),
    )
    .unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::super::super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::super::super::authority_test_support::prepare_request_for_provider(
                &launch, &path, 84, "openai",
            ),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        _ => panic!("fresh admission"),
    };
    let lifecycle = reopen_test_store(&path, 100);
    let (_, binding) = lifecycle
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap()
        .split();
    store
        .start_online_effect(&launch, admission.claim(), &binding)
        .unwrap();
    let dispatch = crate::provider::SqliteProviderDispatchStore::open_with_connection(
        path.to_str().unwrap(),
        super::super::super::authority_test_support::configured_connection(&path),
    )
    .unwrap();
    dispatch
        .mark_streaming_online(
            &crate::provider::MarkProviderStreaming {
                attempt_id: admission.claim().attempt_id,
                fencing_token: admission.claim().fencing_token,
                stream_id: runne_provider::ProviderStreamId::from_bytes([85; 16]),
            },
            || 100,
        )
        .unwrap();
    let request = ProviderPollRequest {
        attempt_id: admission.claim().attempt_id,
        fencing_token: admission.claim().fencing_token,
        cursor: 0,
        profile_digest: admission.claim().profile_digest,
        runtime_generation: 11,
    };
    store.begin_provider_poll(&request).unwrap();
    clock.store(219, Ordering::SeqCst);
    store.revalidate_provider_poll(&request).unwrap();
    let connection = super::super::super::authority_test_support::configured_connection(&path);
    connection.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water=200 WHERE provider_id='openai'", []).unwrap();
    clock.store(199, Ordering::SeqCst);
    assert_eq!(
        store.revalidate_provider_poll(&request),
        Err(ProviderExecutionError::StaleGeneration),
        "clock before durable credential observation must fail"
    );
    clock.store(219, Ordering::SeqCst);
    store.revalidate_provider_poll(&request).unwrap();
    connection.execute("INSERT INTO provider_credential_clock_high_water(provider_id, observed_at) VALUES ('openai', 210) ON CONFLICT(provider_id) DO UPDATE SET observed_at=excluded.observed_at", []).unwrap();
    clock.store(209, Ordering::SeqCst);
    assert_eq!(
        store.revalidate_provider_poll(&request),
        Err(ProviderExecutionError::StaleGeneration),
        "provider clock floor must also apply when newer than head"
    );
    clock.store(219, Ordering::SeqCst);
    store.revalidate_provider_poll(&request).unwrap();
    for expired in [220, 221] {
        clock.store(expired, Ordering::SeqCst);
        assert_eq!(
            store.revalidate_provider_poll(&request),
            Err(ProviderExecutionError::StaleGeneration)
        );
    }
    assert!(
        store
            .load_encrypted_events(request.attempt_id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        dispatch
            .get_dispatch(request.attempt_id)
            .unwrap()
            .unwrap()
            .state,
        crate::provider::ProviderDispatchState::Streaming
    );
}
