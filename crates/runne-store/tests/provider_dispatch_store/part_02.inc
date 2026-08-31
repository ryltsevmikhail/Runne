
#[test]
fn settlement_is_idempotent_and_conflicting_settlement_preserves_original() {
    let (database, store, launch) = fresh_store("settlement");
    store.persist_prepared(&launch, &prepared(1)).unwrap();
    let dispatch_claim = issue_dispatch(&database, 1);
    store
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: dispatch_claim.attempt_id,
            fencing_token: dispatch_claim.fencing_token,
            stream_id: ProviderStreamId::from_bytes([10; 16]),
        })
        .unwrap();
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };

    ProviderDispatchRepository::mark_terminal_pending(
        &store,
        settlement.attempt_id,
        settlement.fencing_token,
        settlement.settlement_digest,
    )
    .unwrap();
    assert!(
        ProviderDispatchRepository::mark_terminal_pending(
            &store,
            settlement.attempt_id,
            settlement.fencing_token,
            [12; 32],
        )
        .is_err()
    );
    ProviderDispatchRepository::mark_terminal_pending(
        &store,
        settlement.attempt_id,
        settlement.fencing_token,
        settlement.settlement_digest,
    )
    .unwrap();
    assert_eq!(
        store
            .get_dispatch(settlement.attempt_id)
            .unwrap()
            .unwrap()
            .state,
        ProviderDispatchState::TerminalPendingCommit
    );
    assert_eq!(
        store.settle(&settlement).unwrap(),
        ProviderDispatchState::Settled
    );
    assert_eq!(
        store.settle(&settlement).unwrap(),
        ProviderDispatchState::Settled
    );

    let mut conflicting = settlement;
    conflicting.settlement_digest = [12; 32];
    assert_eq!(
        store.settle(&conflicting),
        Err(ProviderStoreError::SettlementConflict)
    );
    assert_eq!(
        store
            .get_dispatch(conflicting.attempt_id)
            .unwrap()
            .unwrap()
            .settlement_digest,
        Some([11; 32])
    );
}

#[test]
fn terminal_settlement_and_uncertainty_race_has_one_authoritative_winner() {
    let (database, first, launch) = fresh_store("terminal-race");
    first.persist_prepared(&launch, &prepared(1)).unwrap();
    let dispatch_claim = issue_dispatch(&database, 1);
    first
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: dispatch_claim.attempt_id,
            fencing_token: dispatch_claim.fencing_token,
            stream_id: ProviderStreamId::from_bytes([10; 16]),
        })
        .unwrap();
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };
    first.mark_terminal_pending(&settlement).unwrap();

    let second = database.dispatch();
    let attempt_id = dispatch_claim.attempt_id;
    let fencing_token = dispatch_claim.fencing_token;
    let barrier = Arc::new(Barrier::new(2));
    let settle_barrier = barrier.clone();
    let settle_thread = std::thread::spawn(move || {
        settle_barrier.wait();
        first.settle(&settlement)
    });
    let uncertain_barrier = barrier.clone();
    let uncertain_thread = std::thread::spawn(move || {
        uncertain_barrier.wait();
        second.mark_uncertain(attempt_id, fencing_token)
    });

    let outcomes = [
        settle_thread.join().unwrap(),
        uncertain_thread.join().unwrap(),
    ];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);

    let final_record = database
        .dispatch()
        .get_dispatch(attempt_id)
        .unwrap()
        .unwrap();
    let winning_state = outcomes.iter().find_map(|outcome| outcome.as_ref().ok());
    assert_eq!(winning_state, Some(&final_record.state));
    assert!(matches!(
        final_record.state,
        ProviderDispatchState::Settled | ProviderDispatchState::Uncertain
    ));
}

#[test]
fn repository_port_commits_terminal_settlement_after_stream_binding() {
    let (database, store, launch) = fresh_store("settlement-port");
    store.persist_prepared(&launch, &prepared(1)).unwrap();
    let dispatch_claim = issue_dispatch(&database, 1);
    store
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: dispatch_claim.attempt_id,
            fencing_token: dispatch_claim.fencing_token,
            stream_id: ProviderStreamId::from_bytes([10; 16]),
        })
        .unwrap();

    ProviderDispatchRepository::mark_terminal_pending(
        &store,
        dispatch_claim.attempt_id,
        dispatch_claim.fencing_token,
        [11; 32],
    )
    .unwrap();
    ProviderDispatchRepository::settle(
        &store,
        dispatch_claim.attempt_id,
        dispatch_claim.fencing_token,
        [11; 32],
    )
    .unwrap();

    let record = store
        .get_dispatch(dispatch_claim.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ProviderDispatchState::Settled);
    assert_eq!(record.settlement_digest, Some([11; 32]));
}

#[test]
fn settlement_before_stream_binding_fails_without_terminal_mutation() {
    let (database, store, launch) = fresh_store("settlement-before-stream");
    store.persist_prepared(&launch, &prepared(1)).unwrap();
    let dispatch_claim = issue_dispatch(&database, 1);
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };

    assert!(store.settle(&settlement).is_err());
    let record = store
        .get_dispatch(dispatch_claim.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ProviderDispatchState::Dispatching);
    assert_eq!(record.settlement_digest, None);
}

#[test]
fn settlement_before_terminal_evidence_preserves_streaming_state() {
    let (database, store, launch) = fresh_store("settlement-before-terminal");
    store.persist_prepared(&launch, &prepared(1)).unwrap();
    let dispatch_claim = issue_dispatch(&database, 1);
    store
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: dispatch_claim.attempt_id,
            fencing_token: dispatch_claim.fencing_token,
            stream_id: ProviderStreamId::from_bytes([10; 16]),
        })
        .unwrap();
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };

    assert_eq!(
        store.settle(&settlement),
        Err(ProviderStoreError::SettlementBeforeTerminal)
    );
    let record = store
        .get_dispatch(dispatch_claim.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ProviderDispatchState::Streaming);
    assert_eq!(record.settlement_digest, None);
}

#[test]
fn pre_effect_rejection_is_terminal_exact_and_never_becomes_streaming() {
    let (database, store, launch) = fresh_store("pre-effect-rejection");
    store.persist_prepared(&launch, &prepared(1)).unwrap();
    let dispatch_claim = issue_dispatch(&database, 1);

    ProviderDispatchRepository::mark_rejected_before_effect(
        &store,
        dispatch_claim.attempt_id,
        dispatch_claim.fencing_token,
        ProviderPreEffectRejection::CredentialUnavailable,
    )
    .unwrap();
    ProviderDispatchRepository::mark_rejected_before_effect(
        &store,
        dispatch_claim.attempt_id,
        dispatch_claim.fencing_token,
        ProviderPreEffectRejection::CredentialUnavailable,
    )
    .unwrap();

    let record = store
        .get_dispatch(dispatch_claim.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ProviderDispatchState::RejectedBeforeEffect);
    assert_eq!(
        record.pre_effect_rejection,
        Some(ProviderPreEffectRejection::CredentialUnavailable)
    );
    assert!(
        ProviderDispatchRepository::mark_rejected_before_effect(
            &store,
            dispatch_claim.attempt_id,
            dispatch_claim.fencing_token,
            ProviderPreEffectRejection::CredentialAccessDenied,
        )
        .is_err()
    );
    assert!(
        store
            .mark_streaming(&MarkProviderStreaming {
                attempt_id: dispatch_claim.attempt_id,
                fencing_token: dispatch_claim.fencing_token,
                stream_id: ProviderStreamId::from_bytes([10; 16]),
            })
            .is_err()
    );
}
