    // ── 8. recovery_blocked_state ───────────────────────────────
    #[test]
    fn recovery_blocked_state() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Bootstrap once to create the DB
        let o1 = bootstrap(&config).unwrap();
        drop(o1);

        // Insert a synthetic event directly into the DB
        {
            let conn = schema::open_with_pragmas(&config.db_path).unwrap();
            // Insert into aggregate_streams so FK is satisfied
            conn.execute(
                "INSERT OR IGNORE INTO aggregate_streams
                 (aggregate_type, aggregate_id, current_version, created_at)
                 VALUES (1, x'00000000000000000000000000000042', 1, 0)",
                [],
            )
            .unwrap();
            // Insert an event
            conn.execute(
                "INSERT INTO events
                 (event_id, aggregate_type, aggregate_id, sequence, global_position,
                  timestamp, sensitivity, schema_version, command_id, idempotency_key,
                  actor, payload, integrity_digest, correlation_id, correlation_type,
                  integrity_profile)
                 VALUES
                 (randomblob(16), 1, x'00000000000000000000000000000042', 1, 1,
                  0, 0, 1, randomblob(16), x'01', x'02', x'03', randomblob(32),
                  randomblob(16), 1, 1)",
                [],
            )
            .unwrap();
            conn.close().unwrap();
        }

        // Now call enumerate_recovery_tasks — should be RecoveryBlocked
        use crate::recovery::enumerate_recovery_tasks;
        let conn = schema::open_with_pragmas(&config.db_path).unwrap();
        let state = enumerate_recovery_tasks(&conn).unwrap();
        assert_eq!(state, crate::recovery::RecoveryState::RecoveryBlocked);
    }

    #[cfg(unix)]
    #[test]
    fn prepared_first_activation_preflight_accepts_each_safe_sidecar_crash_window() {
        use gocode_api::{
            ExecutableIdentityV1, PendingFirstActivationV1, ProtectedRuntimeProfileV1,
            StableRuntimeBindingV1,
        };

        let authority = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 1,
        ];
        let pending = PendingFirstActivationV1::new(
            [
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 3,
            ],
            [0x10; 32],
            StableRuntimeBindingV1::new(
                authority,
                "local-owner",
                [
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 2,
                ],
                "gocode-ui-client/2",
                [0x20; 32],
                [0x30; 32],
            )
            .unwrap(),
            ExecutableIdentityV1::new([0x40; 32], [0x50; 32], 4_096).unwrap(),
            ProtectedRuntimeProfileV1::new(
                "gocode-bundled-runtime/1",
                1,
                "gocode-ui-client/2",
                [0x20; 32],
                [0x30; 32],
            )
            .unwrap(),
        )
        .unwrap();
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let launch = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 4,
        ];
        bootstrap_protected(
            &config,
            launch,
            [0x61; 32],
            pending.stable(),
            Some(&pending),
            || {
            Err(DaemonError::Bootstrap(
                "protected launch authority expired".into(),
            ))
            },
        )
        .expect_err("injected failure before consumption");

        let replay_key_path = Path::new(&config.replay_integrity_key_path);
        let authority_path = replay_key_path.with_file_name("local-session-authority-id");
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("complete unconsumed sidecars");

        let expected_lineage = uuid::Uuid::from_bytes(*pending.stable().lineage_id())
            .to_string()
            .parse()
            .unwrap();
        let connection = schema::open_existing_with_pragmas_validated(
            Path::new(&config.db_path),
            |connection| {
                schema::preflight_first_activation_resume(
                    connection,
                    pending.stable().authority_id(),
                    expected_lineage,
                    pending.preparation_id(),
                )?;
                Ok(())
            },
        )
        .unwrap();
        connection
            .execute(
                "DELETE FROM _daemon_info WHERE key = ?1",
                [SIDECAR_MIGRATION_MARKER_KEY],
            )
            .unwrap();
        drop(connection);
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("crash before marker");

        fs::remove_file(&authority_path).unwrap();
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("crash before authority sidecar");
        load_or_provision_local_session_authority(&authority_path, authority).unwrap();

        fs::remove_file(replay_key_path).unwrap();
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("crash before replay-key sidecar");
        fs::remove_file(&authority_path).unwrap();
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("crash before either sidecar");

        fs::write(replay_key_path, [0x7f; 7]).unwrap();
        assert!(preflight_recoverable_first_activation_sidecars(&config, &authority).is_err());
    }
