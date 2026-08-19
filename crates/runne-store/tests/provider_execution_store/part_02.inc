
#[test]
fn authority_restart_atomically_freezes_old_live_attempt_before_new_lease_is_usable() {
    let database = validated_reopen::ProviderTestDatabase::new("provider-generation-restart");
    let (store, request) = initialize(&database);
    let ProviderAuthorityIssueOutcome::Winner(admitted) = store.issue(&request).unwrap() else {
        panic!("first generation must admit one attempt")
    };
    let attempt_id = admitted.claim().attempt_id;
    database
        .dispatch()
        .mark_streaming(&runne_store::provider::MarkProviderStreaming {
            attempt_id,
            fencing_token: admitted.claim().fencing_token,
            stream_id: runne_provider::ProviderStreamId::from_bytes([41; 16]),
        })
        .unwrap();

    let mut restarted = config();
    restarted.generation = 12;
    restarted.fencing_token = 14;
    store
        .install_runtime_authority_and_advance_worker_lease(&restarted)
        .unwrap();

    let reopened = database
        .dispatch()
        .get_dispatch(attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened.state,
        runne_store::provider::ProviderDispatchState::Uncertain
    );
    assert!(
        database
            .dispatch()
            .mark_streaming(&runne_store::provider::MarkProviderStreaming {
                attempt_id,
                fencing_token: admitted.claim().fencing_token,
                stream_id: runne_provider::ProviderStreamId::from_bytes([42; 16]),
            })
            .is_err()
    );
    assert_eq!(
        store.issue(&request),
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
    let (_store, request) = initialize(&database);
    let first = database.execution();
    let second = database.execution();
    let barrier = Arc::new(Barrier::new(3));

    let first_barrier = Arc::clone(&barrier);
    let first_request = request.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first.issue(&first_request)
    });
    let second_barrier = Arc::clone(&barrier);
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second.issue(&request)
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
    let (store, _) = initialize(&database);
    let key = ProviderJournalKeyBinding::new([21; 16], 1, [1; 16], 7).unwrap();

    assert_eq!(store.active_journal_key_binding().unwrap(), None);
    store.activate_journal_key(key).unwrap();
    assert_eq!(store.active_journal_key_binding().unwrap(), Some(key));
}
