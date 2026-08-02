
#[test]
fn every_terminal_transaction_write_edge_rolls_back_to_the_streaming_snapshot() {
    let failure_edges = [
        (
            "terminal_nonce",
            "BEFORE INSERT ON provider_encryption_nonces
             WHEN NEW.purpose = 2",
        ),
        (
            "accounting",
            "BEFORE INSERT ON provider_accounting_settlements",
        ),
        ("outbox", "BEFORE INSERT ON provider_terminal_outbox"),
        (
            "reservation_release",
            "BEFORE UPDATE ON provider_budget_reservations
             WHEN OLD.state = 1 AND NEW.state = 2",
        ),
        (
            "authority_budget_release",
            "BEFORE UPDATE ON provider_runtime_authority_state
             WHEN NEW.token_budget_reserved < OLD.token_budget_reserved",
        ),
        (
            "attempt_terminal",
            "BEFORE UPDATE ON provider_dispatch_attempts
             WHEN OLD.state = 3 AND NEW.state = 4",
        ),
    ];

    for (name, trigger_edge) in failure_edges {
        let fixture = fixture();
        arm_poll(&fixture, 0).unwrap();
        fixture
            .execution
            .append_encrypted_event(&event(&fixture, 0, 20, true))
            .unwrap();
        let before = terminal_state_snapshot(&fixture);
        assert_eq!(before.attempt_state, 3);
        assert_eq!(before.live_reservations, 2);

        let connection = Connection::open(&fixture.path).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TRIGGER fail_{name}
                 {trigger_edge}
                 BEGIN SELECT RAISE(ABORT, 'injected terminal failure'); END;"
            ))
            .unwrap();
        drop(connection);

        assert!(
            fixture
                .execution
                .commit_terminal(&terminal_request(&fixture))
                .is_err(),
            "{name} failure must fail closed"
        );
        assert_eq!(
            terminal_state_snapshot(&fixture),
            before,
            "{name} failure left a partial terminal transaction"
        );
    }
}

#[test]
fn retired_key_cannot_be_removed_while_journal_or_outbox_references_it() {
    let fixture = fixture();
    arm_poll(&fixture, 0).unwrap();
    fixture
        .execution
        .append_encrypted_event(&event(&fixture, 0, 20, false))
        .unwrap();
    let replacement = ProviderJournalKeyBinding::new([11; 16], 2, [1; 16], 7).unwrap();
    fixture.execution.activate_journal_key(replacement).unwrap();

    assert_eq!(
        fixture
            .execution
            .journal_key_reference_count(fixture.key)
            .unwrap(),
        1
    );
    assert_eq!(
        fixture.execution.remove_retired_journal_key(fixture.key),
        Err(ProviderExecutionError::JournalKeyUnavailable)
    );
    assert_eq!(
        fixture.execution.remove_retired_journal_key(replacement),
        Err(ProviderExecutionError::JournalKeyUnavailable)
    );
}
