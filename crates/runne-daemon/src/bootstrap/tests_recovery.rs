    // ── 8. recovery_blocked_state ───────────────────────────────
    #[test]
    fn recovery_blocked_state() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Bootstrap once to create the DB
        let o1 = bootstrap(&config).unwrap();
        let authority_id = o1.authority_id;
        drop(o1);

        // Commit one structurally valid event through the production repository.
        use runne_application::ports::ProjectWorkspaceRepository as _;
        let prohibited = std::sync::Arc::new(
            runne_security::SecretBroker::new().prohibited_content_guard(),
        );
        let store = runne_store::store::StoreTransaction::open(
            &config.db_path,
            runne_application::ports::RuntimeAuthorityId(hex::encode(authority_id)),
            prohibited,
        )
        .unwrap();
        let project_id = runne_domain::id::ProjectId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x42,
        ]);
        let repository = runne_store::ProjectWorkspaceStore::from_store(store.clone());
        repository
            .create_project(
                "local-owner",
                runne_domain::id::CommandId::from_bytes([
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x43,
                ]),
                &runne_domain::id::IdempotencyKey::new("recovery-project").unwrap(),
                runne_domain::project_workspace::Project::create(
                    project_id,
                    runne_domain::project_workspace::ProjectWorkspaceDisplayName::new(
                        "Recovery project".into(),
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
        let workspace_id = runne_domain::id::WorkspaceId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x44,
        ]);
        repository
            .create_workspace(
                "local-owner",
                runne_domain::id::CommandId::from_bytes([
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x45,
                ]),
                &runne_domain::id::IdempotencyKey::new("recovery-workspace").unwrap(),
                runne_domain::project_workspace::Workspace::create(
                    workspace_id,
                    project_id,
                    runne_domain::project_workspace::ProjectWorkspaceDisplayName::new(
                        "Recovery workspace".into(),
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
        let command_id = runne_domain::id::CommandId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x46,
        ]);
        let key = runne_domain::id::IdempotencyKey::new("recovery-conversation").unwrap();
        runne_application::conversation_service::ConversationService::new(
            store.clone(),
            store,
            runne_application::ports::RuntimeAuthorityId(hex::encode(authority_id)),
        )
        .create_from_application(
            &runne_application::ports::ApplicationCommandContext {
                command_id,
                idempotency_key: key.clone(),
                principal_id: runne_application::ports::PrincipalId("local-owner".into()),
                actor: runne_domain::event::Actor::new("recovery-test").unwrap(),
            },
            runne_api::CreateConversationInput {
                conversation_id: runne_domain::id::ConversationId::from_bytes([
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x47,
                ]),
                workspace_id,
                command_id,
                idempotency_key: key,
            },
        )
        .unwrap();

        // Now call enumerate_recovery_tasks — should be RecoveryBlocked
        use crate::recovery::enumerate_recovery_tasks;
        let conn = schema::reopen_managed_connection_validated(
            Path::new(&config.db_path),
            schema::ConnectionMode::Reader,
            |connection| {
                if schema::read_authority_id(connection)? == Some(authority_id) {
                    Ok(())
                } else {
                    Err(rusqlite::Error::InvalidQuery)
                }
            },
        )
        .unwrap();
        schema::readiness_from_managed(&conn).unwrap();
        schema::publication_from_managed(&conn).unwrap();
        let state = enumerate_recovery_tasks(&conn).unwrap();
        assert_eq!(state, crate::recovery::RecoveryState::RecoveryBlocked);
    }

    #[cfg(unix)]
    #[test]
    fn prepared_first_activation_preflight_accepts_each_safe_sidecar_crash_window() {
        use runne_api::{
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
                runne_api::PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
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
        let connection = schema::reopen_managed_connection_validated(
            Path::new(&config.db_path),
            schema::ConnectionMode::ValidatedReopen,
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
