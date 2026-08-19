#[test]
fn mark_streaming_exact_replay_and_conflict_preserve_record() {
    let (_d, store, claim) = setup("streaming-replay");
    let request = MarkStreaming {
        attempt_id: claim.attempt_id,
        fencing_token: claim.fencing_token,
        stream_id: Stream::from_bytes([10; 16]),
    };
    assert_eq!(store.mark_streaming(&request), Ok(Streaming));
    let before = snapshot(&store, claim.attempt_id);

    assert_eq!(store.mark_streaming(&request), Ok(Streaming));
    assert_eq!(snapshot(&store, claim.attempt_id), before);

    let conflicting = MarkStreaming {
        stream_id: Stream::from_bytes([11; 16]),
        ..request
    };
    assert_eq!(
        store.mark_streaming(&conflicting),
        Err(Error::StreamConflict)
    );
    assert_eq!(snapshot(&store, claim.attempt_id), before);
}

#[test]
fn lifecycle_missing_attempts_return_not_found_without_row_creation() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(&d.path().join("s")).unwrap();
    let attempt_id = Attempt::from_bytes([99; 16]);
    let streaming = MarkStreaming {
        attempt_id,
        fencing_token: 9,
        stream_id: Stream::from_bytes([10; 16]),
    };
    let settlement = Settlement {
        attempt_id,
        fencing_token: 9,
        settlement_digest: [11; 32],
    };

    assert_eq!(store.mark_streaming(&streaming), Err(Error::NotFound));
    assert_eq!(store.get_dispatch(attempt_id), Ok(None));
    assert_eq!(store.settle(&settlement), Err(Error::NotFound));
    assert_eq!(store.get_dispatch(attempt_id), Ok(None));
}

#[test]
fn lifecycle_stale_fences_preserve_record() {
    let (_d, store, claim) = setup("lifecycle-stale-fence");
    let before = snapshot(&store, claim.attempt_id);
    let stale_fence = claim.fencing_token + 1;

    assert_eq!(
        store.mark_streaming(&MarkStreaming {
            attempt_id: claim.attempt_id,
            fencing_token: stale_fence,
            stream_id: Stream::from_bytes([10; 16]),
        }),
        Err(Error::StaleFencingToken)
    );
    assert_eq!(snapshot(&store, claim.attempt_id), before);
    assert_eq!(
        store.settle(&Settlement {
            attempt_id: claim.attempt_id,
            fencing_token: stale_fence,
            settlement_digest: [11; 32],
        }),
        Err(Error::StaleFencingToken)
    );
    assert_eq!(snapshot(&store, claim.attempt_id), before);
}

#[test]
fn recovery_winner_makes_lifecycle_losers_terminal_without_mutation() {
    let (_d, store, claim) = setup("recovery-terminal");
    assert_eq!(
        store.recover_attempt(claim.attempt_id, claim.fencing_token, Dispatching),
        Ok(TransitionedToUncertain)
    );
    let before = snapshot(&store, claim.attempt_id);

    assert_eq!(
        store.mark_streaming(&MarkStreaming {
            attempt_id: claim.attempt_id,
            fencing_token: claim.fencing_token,
            stream_id: Stream::from_bytes([10; 16]),
        }),
        Err(Error::AlreadyTerminal)
    );
    assert_eq!(snapshot(&store, claim.attempt_id), before);
    assert_eq!(
        store.settle(&Settlement {
            attempt_id: claim.attempt_id,
            fencing_token: claim.fencing_token,
            settlement_digest: [11; 32],
        }),
        Err(Error::AlreadyTerminal)
    );
    assert_eq!(snapshot(&store, claim.attempt_id), before);
}
