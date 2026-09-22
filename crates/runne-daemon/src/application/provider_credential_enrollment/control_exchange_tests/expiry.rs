use super::*;

#[test]
fn rejects_expired_wrong_or_missing_session_and_wrong_peer_before_issue() {
    let bindings = begin_bindings();
    for expected in [
        expectation_with(
            bindings.0,
            native_intent("intent-a"),
            1,
            2,
            uuid(9),
            [11; 32],
            [7; 32],
        ),
        expectation_with(
            bindings.0,
            native_intent("intent-a"),
            1,
            2,
            uuid(2),
            [13; 32],
            [7; 32],
        ),
        expectation_with(
            bindings.0,
            native_intent("intent-a"),
            1,
            2,
            uuid(2),
            [11; 32],
            [13; 32],
        ),
    ] {
        let (exchange, request, admission) = fixture(expected);
        assert!(
            exchange
                .register(request, admission, context(), 110_000, provider())
                .is_err()
        );
    }

    let (exchange, request, admission) = fixture(expectation());
    assert!(
        exchange
            .register(request, admission, context(), 120_000, provider())
            .is_err()
    );
    assert!(
        DaemonCredentialHttpAdmissionExpectation::new(
            [0; 16],
            [10; 32],
            [8; 32],
            [9; 32],
            native_intent("intent-a"),
            1,
            2,
            [7; 32],
            120_000,
        )
        .is_err()
    );
}
