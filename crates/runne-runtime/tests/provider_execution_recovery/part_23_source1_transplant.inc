fn source1_proof_macs(fixture: &Fixture) -> ([u8; 32], [u8; 32]) {
    let connection = validated_connection(fixture);
    connection
        .query_row(
            "SELECT issuance.issuance_mac,effect.effect_mac
             FROM provider_online_dispatch_issuance_evidence issuance
             JOIN provider_online_credential_effect_bindings effect
               ON effect.dispatch_attempt_id=issuance.dispatch_attempt_id
             WHERE issuance.dispatch_attempt_id=?1",
            [fixture.attempt_id.as_bytes().as_slice()],
            |row| {
                let issuance: Vec<u8> = row.get(0)?;
                let effect: Vec<u8> = row.get(1)?;
                Ok((
                    issuance
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    effect
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                ))
            },
        )
        .unwrap()
}

async fn complete_source1_unknown_fixture(fixture: &Fixture) {
    let keyring = fixture.keyring();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let mut events = successful_events("source1-proof-transplant");
    events[2] = ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap();
    poll_events(&runtime, fixture, events).await;
}

#[tokio::test(flavor = "current_thread")]
async fn source1_rejects_issuance_and_effect_proofs_transplanted_from_other_attempt() {
    let donor = fixture();
    let recipient = fixture();
    assert_ne!(donor.taskrun_id, recipient.taskrun_id);
    assert_ne!(donor.execution_attempt_id, recipient.execution_attempt_id);
    assert_ne!(donor.attempt_id, recipient.attempt_id);
    complete_source1_unknown_fixture(&donor).await;
    complete_source1_unknown_fixture(&recipient).await;

    let donor_keyring = donor.keyring();
    let donor_runtime = runtime(&donor_keyring, donor.execution.as_ref());
    assert_eq!(
        donor_runtime.finalize_terminal_output(&context(&donor)),
        Ok(ProviderTerminalCommitOutcome::Committed),
        "the donor issuance/effect proofs must be lawfully accepted before transplant"
    );
    let (donor_issuance, donor_effect) = source1_proof_macs(&donor);
    let (recipient_issuance, recipient_effect) = source1_proof_macs(&recipient);
    assert_ne!(donor_issuance, recipient_issuance);
    assert_ne!(donor_effect, recipient_effect);

    let connection = rusqlite::Connection::open(&recipient.path).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER provider_online_dispatch_issuance_evidence_immutable;
             DROP TRIGGER provider_online_credential_effect_binding_immutable;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE provider_online_dispatch_issuance_evidence SET issuance_mac=?1
             WHERE dispatch_attempt_id=?2",
            rusqlite::params![
                donor_issuance.as_slice(),
                recipient.attempt_id.as_bytes().as_slice()
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE provider_online_credential_effect_bindings SET effect_mac=?1
             WHERE dispatch_attempt_id=?2",
            rusqlite::params![
                donor_effect.as_slice(),
                recipient.attempt_id.as_bytes().as_slice()
            ],
        )
        .unwrap();
    drop(connection);

    let recipient_keyring = recipient.keyring();
    let recipient_runtime = runtime(&recipient_keyring, recipient.execution.as_ref());
    assert_eq!(
        recipient_runtime.finalize_terminal_output(&context(&recipient)),
        Err(RuntimeProviderExecutionError::JournalCorrupt),
        "proofs minted for a different lawful attempt cannot authorize this attempt"
    );
    let connection = rusqlite::Connection::open(&recipient.path).unwrap();
    for table in [
        "provider_unknown_terminal_receipts",
        "provider_terminal_outbox",
        "provider_accounting_settlements",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "transplanted proofs must not create {table}"
        );
    }
    assert_eq!(
        connection
            .prepare("SELECT state,settled_amount,released_at FROM provider_budget_reservations ORDER BY dimension")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, Option<i64>>(2)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap(),
        vec![(1, None, None), (1, None, None)]
    );
}
