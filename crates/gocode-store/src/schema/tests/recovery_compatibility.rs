    // Task 6 status ledger:
    // 8 covered: released V8 migration/open is tested below.
    // 10 partial: local current preflight is covered externally; the historical
    // old-binary portion is blocked because no historical-binary harness exists.
    // 11 blocked: rollback with an authority switch is not implemented or qualified.

    #[test]
    fn recovery_compatibility_status_8_covered_released_v8_upgrade_open_preserves_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("released-v8.sqlite");
        let conn = Connection::open(&path).unwrap();
        initialize_released_v8(&conn);
        conn.execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (1, ?1, 1, ?2, 0, 0)",
            params![TEST_ID, [0x24_u8; 16]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile)
             VALUES (?1, 1, ?2, 1, 1, 0, 0, 1, NULL, ?3, x'01', x'02', x'03', ?4, ?2, 1, 1)",
            params![[0x24_u8; 16], TEST_ID, [0x25_u8; 16], [0x26_u8; 32]],
        )
            .unwrap();
        let before: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = conn
            .query_row(
                "SELECT event_id, aggregate_id, global_position, integrity_digest FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        drop(conn);

        preflight_existing_file(&path).unwrap();
        let conn = open_with_pragmas(path.to_str().unwrap()).unwrap();

        apply_migrations(&conn).unwrap();

        let after: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = conn
            .query_row(
                "SELECT event_id, aggregate_id, global_position, integrity_digest FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(after, before);
        assert_eq!(
            conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            CURRENT_SCHEMA_VERSION
        );
    }
