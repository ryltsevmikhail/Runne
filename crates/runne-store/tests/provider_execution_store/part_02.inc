
#[test]
fn authority_restart_atomically_freezes_old_live_attempt_before_new_lease_is_usable() {
    let database = validated_reopen::ProviderTestDatabase::new("provider-generation-restart");
    let (store, launch, request) = initialize(&database);
    let (binding, _) = online_stream_fixture::start(&database, &store, &launch, prepared().2, &request, runne_provider::ProviderStreamId::from_bytes([41; 16]), 83);
    let attempt_id = binding.execution().attempt_id();

    let mut restarted = config();
    restarted.generation = 12;
    restarted.fencing_token = 14;
    let restarted_launch = store.activate_runtime_launch(&restarted).unwrap();

    let reopened = database
        .dispatch()
        .get_dispatch(attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened.state,
        runne_store::provider::ProviderDispatchState::Uncertain
    );
    assert_eq!(
        store.begin_provider_poll(&runne_application::provider::ProviderPollRequest {
                attempt_id,
                fencing_token: binding.execution().fencing_token(),
                cursor: 0,
                profile_digest: request.prepared.profile_digest,
                runtime_generation: 11,
            }),
        Err(runne_application::provider::ProviderExecutionError::StaleGeneration),
    );
    assert_eq!(
        store.issue(&restarted_launch, &request),
        Ok(ProviderAuthorityIssueOutcome::Existing {
            state: runne_provider::ProviderRepositoryState::Uncertain,
        })
    );

    let connection = database.connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_budget_reservations WHERE released_at IS NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    let (tokens, cost) = store.utilization().unwrap();
    assert_eq!(
        (tokens.limit, tokens.reserved, tokens.settled),
        (10_000, 1_536, 0)
    );
    assert_eq!(
        (cost.limit, cost.reserved, cost.settled),
        (1_000_000, 50_000, 0)
    );
}

#[test]
fn begin_immediate_allows_one_winner_across_two_store_handles() {
    let database = validated_reopen::ProviderTestDatabase::new("provider-two-writer");
    let (_store, launch, request) = initialize(&database);
    let first = database.execution();
    arm(&first);
    let second = database.execution();
    arm(&second);
    let barrier = Arc::new(Barrier::new(3));

    let first_barrier = Arc::clone(&barrier);
    let first_launch = Arc::clone(&launch);
    let first_request = request.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first.issue(&first_launch, &first_request)
    });
    let second_barrier = Arc::clone(&barrier);
    let second_launch = Arc::clone(&launch);
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second.issue(&second_launch, &request)
    });
    barrier.wait();

    let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ProviderAuthorityIssueOutcome::Winner(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ProviderAuthorityIssueOutcome::Existing { .. })))
            .count(),
        1
    );
}

#[test]
fn active_journal_key_preflight_returns_only_the_exact_non_secret_binding() {
    let database = validated_reopen::ProviderTestDatabase::new("provider-key-preflight");
    let store = database.execution();
    let _launch = store.activate_runtime_launch(&config()).unwrap();
    let key = ProviderJournalKeyBinding::new([21; 16], 1, [1; 16], 7).unwrap();

    assert_eq!(store.active_journal_key_binding().unwrap(), None);
    assert_eq!(
        store.activate_journal_key(key),
        Err(runne_application::provider::ProviderExecutionError::JournalKeyUnavailable)
    );
    crate::online_proof::activate(&store, key);
    assert_eq!(store.active_journal_key_binding().unwrap(), Some(key));
}
