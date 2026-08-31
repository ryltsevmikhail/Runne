#[test]
fn every_fault_point_has_static_disposition_and_reopens_authoritative_state() {
    for fault in [
        RecoveryFaultPoint::BeforeClaim,
        RecoveryFaultPoint::AfterClaimBeforeDispatch,
        RecoveryFaultPoint::AfterSimulatedDispatchBeforeStreaming,
        RecoveryFaultPoint::AfterStreamingBeforeSettle,
        RecoveryFaultPoint::AfterSettleBeforeAcknowledgement,
    ] {
        let (directory, store, claim) = prepared_setup("task4-fault");
        let path = directory.as_path().to_path_buf();
        let provider = CountingProvider::new();
        let streaming = stream_request(&claim);
        let settlement = settlement_request(&claim);

        {
            let decorator = RecoveryFaultDecorator::new(
                directory.as_path().to_path_buf(),
                &store,
                &provider,
                fault,
            );
            match fault {
                RecoveryFaultPoint::BeforeClaim | RecoveryFaultPoint::AfterClaimBeforeDispatch => {
                    assert_eq!(
                        decorator.claim(&claim),
                        Err(RecoveryTestDisposition::Injected(fault))
                    );
                }
                RecoveryFaultPoint::AfterSimulatedDispatchBeforeStreaming => {
                    decorator.claim(&claim).unwrap();
                    assert_eq!(
                        decorator.mark_streaming(&streaming),
                        Err(RecoveryTestDisposition::Injected(fault))
                    );
                }
                RecoveryFaultPoint::AfterStreamingBeforeSettle => {
                    decorator.claim(&claim).unwrap();
                    assert_eq!(
                        decorator.mark_streaming(&streaming),
                        Err(RecoveryTestDisposition::Injected(fault))
                    );
                }
                RecoveryFaultPoint::AfterSettleBeforeAcknowledgement => {
                    decorator.claim(&claim).unwrap();
                    assert_eq!(decorator.mark_streaming(&streaming), Ok(Streaming));
                    store.mark_terminal_pending(&settlement).unwrap();
                    assert_eq!(
                        decorator.settle(&settlement),
                        Err(RecoveryTestDisposition::Injected(fault))
                    );
                }
            }
        }

        if fault == RecoveryFaultPoint::BeforeClaim {
            assert_eq!(store.get_dispatch(claim.attempt_id), Ok(None));
            provider.assert_count(0);
            continue;
        }
        let reopened = &store;
        let before_recovery = DispatchSnapshot::load(&path, claim.attempt_id);
        match before_recovery.state {
            Dispatching => {
                assert_eq!(
                    reopened.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching),
                    Ok(TransitionedToUncertain)
                );
                let after_recovery = DispatchSnapshot::load(&path, claim.attempt_id);
                DispatchSnapshot::assert_transition(
                    &before_recovery,
                    &after_recovery,
                    Uncertain,
                    None,
                    None,
                );
            }
            Streaming => {
                assert_eq!(
                    reopened.recover_attempt(claim.attempt_id, claim.fencing_token, Streaming),
                    Ok(TransitionedToUncertain)
                );
                let after_recovery = DispatchSnapshot::load(&path, claim.attempt_id);
                DispatchSnapshot::assert_transition(
                    &before_recovery,
                    &after_recovery,
                    Uncertain,
                    before_recovery.stream_id,
                    None,
                );
            }
            Settled => {
                assert_eq!(
                    reopened.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching),
                    Ok(AlreadySettled)
                );
                assert_eq!(
                    DispatchSnapshot::load(&path, claim.attempt_id),
                    before_recovery
                );
            }
            Uncertain => unreachable!(),
            RejectedBeforeEffect | TerminalPendingCommit => unreachable!(),
        }
        provider.assert_count(usize::from(
            fault != RecoveryFaultPoint::AfterClaimBeforeDispatch,
        ));
    }
}
