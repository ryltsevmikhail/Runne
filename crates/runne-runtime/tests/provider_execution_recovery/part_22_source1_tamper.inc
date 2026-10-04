#[tokio::test(flavor = "current_thread")]
async fn source1_corrupt_original_issuance_rejects_before_unknown_receipt() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.preflight_existing_active_key([1; 16], 7).unwrap();
    let mut events = successful_events("source1-corrupt-original-issuance");
    events[2] = ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap();
    poll_events(&writer, &fixture, events).await;

    // Deliberately corrupt only an existing valid issuance proof row. Drop
    // its update guard in this negative fixture so the validator, rather than
    // the append-only trigger, must reject the broken original proof.
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_online_dispatch_issuance_evidence
                 WHERE dispatch_attempt_id=?1 AND length(issuance_mac)=32",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    connection
        .execute_batch("DROP TRIGGER provider_online_dispatch_issuance_evidence_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_online_dispatch_issuance_evidence SET issuance_mac=?1
             WHERE dispatch_attempt_id=?2",
            rusqlite::params![
                [0xA5_u8; 32].as_slice(),
                fixture.attempt_id.as_bytes().as_slice()
            ],
        )
        .unwrap();
    drop(connection);

    assert_eq!(
        writer.finalize_terminal_output(&context(&fixture)),
        Err(RuntimeProviderExecutionError::JournalCorrupt),
        "the source validator classifies the corrupted original issuance as journal corruption"
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
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
            "invalid original issuance must not create {table}"
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
        vec![(1, None, None), (1, None, None)],
        "failed Source1 verification preserves both original held reserves"
    );
}

#[derive(Clone, Copy, Debug)]
enum OriginalProofTamper {
    EffectMac,
    Principal,
    PreparedHeader,
}

impl OriginalProofTamper {
    fn expected_error(self) -> RuntimeProviderExecutionError {
        match self {
            Self::EffectMac => RuntimeProviderExecutionError::JournalCorrupt,
            Self::Principal => RuntimeProviderExecutionError::TerminalRejected,
            Self::PreparedHeader => RuntimeProviderExecutionError::JournalCorrupt,
        }
    }
}

fn corrupt_existing_original_proof(fixture: &Fixture, tamper: OriginalProofTamper) {
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    match tamper {
        OriginalProofTamper::EffectMac => {
            connection
                .execute_batch("DROP TRIGGER provider_online_credential_effect_binding_immutable")
                .unwrap();
            connection
                .execute(
                    "UPDATE provider_online_credential_effect_bindings SET effect_mac=?1
                     WHERE dispatch_attempt_id=?2",
                    rusqlite::params![
                        [0xA6_u8; 32].as_slice(),
                        fixture.attempt_id.as_bytes().as_slice()
                    ],
                )
                .unwrap();
        }
        OriginalProofTamper::Principal => {
            connection
                .execute(
                    "UPDATE provider_execution_admissions SET principal_id='tampered-principal'
                     WHERE dispatch_attempt_id=?1",
                    [fixture.attempt_id.as_bytes().as_slice()],
                )
                .unwrap();
        }
        OriginalProofTamper::PreparedHeader => {
            connection
                .execute(
                    "UPDATE provider_execution_admissions SET profile_digest=?1
                     WHERE dispatch_attempt_id=?2",
                    rusqlite::params![
                        [0xA7_u8; 32].as_slice(),
                        fixture.attempt_id.as_bytes().as_slice()
                    ],
                )
                .unwrap();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn source1_corrupt_effect_principal_and_prepared_header_never_commit_unknown() {
    for tamper in [
        OriginalProofTamper::EffectMac,
        OriginalProofTamper::Principal,
        OriginalProofTamper::PreparedHeader,
    ] {
        let fixture = fixture();
        let keyring = fixture.keyring();
        let writer = runtime(&keyring, fixture.execution.as_ref());
        writer.preflight_existing_active_key([1; 16], 7).unwrap();
        let mut events = successful_events("source1-corrupt-original-binding");
        events[2] = ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap();
        poll_events(&writer, &fixture, events).await;
        corrupt_existing_original_proof(&fixture, tamper);

        assert_eq!(
            writer.finalize_terminal_output(&context(&fixture)),
            Err(tamper.expected_error()),
            "tampered original {tamper:?} must fail exact source verification"
        );
        let connection = rusqlite::Connection::open(&fixture.path).unwrap();
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
                "invalid original proof must not create {table}"
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
}
