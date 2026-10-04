fn v62_preserved_rows(fixture: &Fixture) -> SqlSnapshot {
    sql_snapshot(&validated_connection(fixture))
        .into_iter()
        .filter(|(table, _)| table != "schema_version" && table != "schema_upgrade_write_latch")
        .collect()
}

fn assert_lawful_v62_source_rows(fixture: &Fixture) {
    let connection = validated_connection(fixture);
    for (table, expected) in [
        ("events", 1),
        ("taskrun_claim_receipts", 1),
        ("provider_execution_admissions", 1),
        ("provider_online_dispatch_issuance_evidence", 1),
        ("provider_stream_journal", 4),
        ("provider_budget_reservations", 2),
    ] {
        let actual = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert!(
            actual >= expected,
            "the v62 fixture must retain {table} rows"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn populated_v62_snapshot_upgrades_and_commits_unknown_with_and_without_v19_marker() {
    for omit_v19_marker in [false, true] {
        let fixture = fixture();
        let keyring = fixture.keyring();
        let writer = runtime(&keyring, fixture.execution.as_ref());
        writer.preflight_existing_active_key([1; 16], 7).unwrap();
        let mut events = successful_events("source1-v62-populated-upgrade");
        events[2] = ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap();
        poll_events(&writer, &fixture, events).await;

        assert_lawful_v62_source_rows(&fixture);
        let before = v62_preserved_rows(&fixture);
        let connection = rusqlite::Connection::open(&fixture.path).unwrap();
        v62_provider_terminal_upgrade::remove_v63_for_v62_upgrade(&connection, omit_v19_marker);
        let downgraded_markers = connection
            .query_row(
                "SELECT MAX(version),COUNT(*) FROM schema_version",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap();
        assert_eq!(downgraded_markers.0, 62);
        if omit_v19_marker {
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM schema_version WHERE version=19",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
        drop(connection);

        // Opening this validated v62 connection exercises the ordinary schema
        // matcher; StoreTransaction then runs the production migration path.
        let store = runne_store::store::StoreTransaction::open_with_connections(
            fixture.path.to_str().unwrap(),
            validated_reopen::open_validated_connection(
                fixture.path.to_str().unwrap(),
                fixture.identity,
            )
            .unwrap(),
            validated_reopen::open_validated_reader(
                fixture.path.to_str().unwrap(),
                fixture.identity,
            )
            .unwrap(),
            runne_application::ports::RuntimeAuthorityId(hex::encode([1; 16])),
            Arc::new(AllowingGuard),
        )
        .unwrap();
        drop(store);
        assert_eq!(
            validated_connection(&fixture)
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            63
        );
        assert_eq!(v62_preserved_rows(&fixture), before);

        assert_eq!(
            writer.finalize_terminal_output(&context(&fixture)),
            Ok(ProviderTerminalCommitOutcome::Committed)
        );
        assert_eq!(
            validated_connection(&fixture)
                .query_row(
                    "SELECT COUNT(*) FROM provider_unknown_terminal_receipts
                     WHERE dispatch_attempt_id=?1 AND usage_present=0 AND accounting_reason=1",
                    [fixture.attempt_id.as_bytes().as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
}
