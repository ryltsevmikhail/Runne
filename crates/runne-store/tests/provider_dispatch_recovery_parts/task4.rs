use recovery_support::{
    CountingProvider, DispatchSnapshot, RecoveryFaultDecorator, RecoveryFaultPoint,
    RecoveryTestDisposition,
};

fn stream_request(claim: &Claim) -> MarkStreaming {
    MarkStreaming {
        attempt_id: claim.attempt_id,
        fencing_token: claim.fencing_token,
        stream_id: Stream::from_bytes([10; 16]),
    }
}

fn settlement_request(claim: &Claim) -> Settlement {
    Settlement {
        attempt_id: claim.attempt_id,
        fencing_token: claim.fencing_token,
        settlement_digest: [11; 32],
    }
}

#[test]
fn ordered_recovery_wins_and_settle_loses_terminally() {
    let (directory, store, claim) = setup("task4-recovery-settle");
    let path = directory.path().join("s");
    let before = DispatchSnapshot::load(&path, claim.attempt_id);
    let settlement = settlement_request(&claim);

    let recovery = store.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching);
    let settlement = store.settle(&settlement);

    assert_eq!(recovery, Ok(TransitionedToUncertain));
    assert_eq!(settlement, Err(Error::AlreadyTerminal));
    let after = DispatchSnapshot::load(&path, claim.attempt_id);
    DispatchSnapshot::assert_transition(&before, &after, Uncertain, None, None);
}

#[test]
fn ordered_recovery_wins_and_streaming_loses_terminally() {
    let (directory, store, claim) = setup("task4-recovery-streaming");
    let path = directory.path().join("s");
    let before = DispatchSnapshot::load(&path, claim.attempt_id);
    let streaming = stream_request(&claim);

    let recovery = store.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching);
    let streaming = store.mark_streaming(&streaming);

    assert_eq!(recovery, Ok(TransitionedToUncertain));
    assert_eq!(streaming, Err(Error::AlreadyTerminal));
    let after = DispatchSnapshot::load(&path, claim.attempt_id);
    DispatchSnapshot::assert_transition(&before, &after, Uncertain, None, None);
}

#[test]
fn ordered_settlement_wins_and_recovery_observes_terminal_evidence() {
    let (directory, store, claim) = setup("task4-settle-recovery");
    let path = directory.path().join("s");
    let before = DispatchSnapshot::load(&path, claim.attempt_id);
    let streaming = stream_request(&claim);
    let settlement = settlement_request(&claim);
    store.mark_streaming(&streaming).unwrap();
    store.mark_terminal_pending(&settlement).unwrap();

    let settlement = store.settle(&settlement);
    let recovery = store.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching);

    assert_eq!(settlement, Ok(Settled));
    assert_eq!(recovery, Ok(AlreadySettled));
    let after = DispatchSnapshot::load(&path, claim.attempt_id);
    DispatchSnapshot::assert_transition(
        &before,
        &after,
        Settled,
        Some(Stream::from_bytes([10; 16])),
        Some([11; 32]),
    );
}

#[test]
fn stale_dispatching_recovery_conflict_requires_fresh_streaming_snapshot() {
    let (directory, store, claim) = setup("task4-streaming-recovery");
    let path = directory.path().join("s");
    let before = DispatchSnapshot::load(&path, claim.attempt_id);
    let streaming = stream_request(&claim);

    let streaming = store.mark_streaming(&streaming);
    let stale_recovery = store.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching);

    assert_eq!(streaming, Ok(Streaming));
    assert_eq!(stale_recovery, Err(Error::RecoveryConflict));
    let streamed = DispatchSnapshot::load(&path, claim.attempt_id);
    DispatchSnapshot::assert_transition(
        &before,
        &streamed,
        Streaming,
        Some(Stream::from_bytes([10; 16])),
        None,
    );

    assert_eq!(DispatchSnapshot::load(&path, claim.attempt_id), streamed);
    assert_eq!(
        store.recover_attempt(claim.attempt_id, claim.fencing_token, Streaming),
        Ok(TransitionedToUncertain)
    );
    let uncertain = DispatchSnapshot::load(&path, claim.attempt_id);
    DispatchSnapshot::assert_transition(&streamed, &uncertain, Uncertain, streamed.stream_id, None);
}

#[test]
fn repeated_recovery_is_idempotent_without_simulated_redispatch() {
    let (directory, store, claim) = prepared_setup("task4-repeat-recovery");
    let path = directory.path().join("s");
    let provider = CountingProvider::new();
    {
        let decorator = RecoveryFaultDecorator::new(
            directory.path().join("s"),
            &store,
            &provider,
            RecoveryFaultPoint::AfterSettleBeforeAcknowledgement,
        );
        assert!(matches!(decorator.claim(&claim), Ok(runne_store::provider::ProviderClaimOutcome::Winner { .. })));
        provider.assert_count(1);
    }
    let before = DispatchSnapshot::load(&path, claim.attempt_id);

    let first_recovery = store.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching);
    let repeated_recovery = store.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching);

    assert_eq!(first_recovery, Ok(TransitionedToUncertain));
    assert_eq!(repeated_recovery, Ok(AlreadyUncertain));
    let after = DispatchSnapshot::load(&path, claim.attempt_id);
    DispatchSnapshot::assert_transition(&before, &after, Uncertain, None, None);
    let retry_before = DispatchSnapshot::load(&path, claim.attempt_id);
    let rows_before = DispatchSnapshot::count(&path, claim.attempt_id);
    assert!(matches!(
        claim_dispatch_row(&path, &claim),
        runne_store::provider::ProviderClaimOutcome::Existing {
            state: Uncertain,
            ..
        }
    ));
    assert_eq!(DispatchSnapshot::load(&path, claim.attempt_id), retry_before);
    assert_eq!(DispatchSnapshot::count(&path, claim.attempt_id), rows_before);
    provider.assert_count(1);
}

#[test]
fn stale_fence_recovery_is_read_only_without_simulated_redispatch() {
    let (directory, store, claim) = prepared_setup("task4-stale-fence");
    let path = directory.path().join("s");
    let provider = CountingProvider::new();
    {
        let decorator = RecoveryFaultDecorator::new(
            directory.path().join("s"),
            &store,
            &provider,
            RecoveryFaultPoint::AfterSettleBeforeAcknowledgement,
        );
        decorator.claim(&claim).unwrap();
        provider.assert_count(1);
    }
    let before = DispatchSnapshot::load(&path, claim.attempt_id);

    assert_eq!(
        store.recover_attempt(claim.attempt_id, claim.fencing_token + 1, Dispatching),
        Err(Error::StaleFencingToken)
    );
    assert_eq!(DispatchSnapshot::load(&path, claim.attempt_id), before);
    provider.assert_count(1);
}

#[test]
fn duplicate_wakeup_and_after_acknowledgement_fault_preserve_single_settlement() {
    let (directory, store, claim) = prepared_setup("task4-duplicate-wakeup");
    let path = directory.path().join("s");
    let provider = CountingProvider::new();
    let streaming = stream_request(&claim);
    let settlement = settlement_request(&claim);

    {
        let decorator = RecoveryFaultDecorator::new(
            directory.path().join("s"),
            &store,
            &provider,
            RecoveryFaultPoint::AfterSettleBeforeAcknowledgement,
        );
        decorator.claim(&claim).unwrap();
        assert_eq!(decorator.mark_streaming(&streaming), Ok(Streaming));
        store.mark_terminal_pending(&settlement).unwrap();
        assert_eq!(
            decorator.settle(&settlement),
            Err(RecoveryTestDisposition::Injected(
                RecoveryFaultPoint::AfterSettleBeforeAcknowledgement
            ))
        );
    }
    let settled = DispatchSnapshot::load(&path, claim.attempt_id);

    {
        let wakeup_before = DispatchSnapshot::load(&path, claim.attempt_id);
        let rows_before = DispatchSnapshot::count(&path, claim.attempt_id);

        assert!(matches!(
            claim_dispatch_row(&path, &claim),
            runne_store::provider::ProviderClaimOutcome::Existing {
                state: Settled,
                ..
            }
        ));
        assert_eq!(DispatchSnapshot::load(&path, claim.attempt_id), wakeup_before);
        assert_eq!(DispatchSnapshot::count(&path, claim.attempt_id), rows_before);
    }
    assert_eq!(
        store.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching),
        Ok(AlreadySettled)
    );
    assert_eq!(DispatchSnapshot::load(&path, claim.attempt_id), settled);
    provider.assert_count(1);
}
