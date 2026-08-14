use std::sync::Arc;

use gocode_api::CreateConversationInput;
use gocode_application::conversation_service::ConversationService;
use gocode_application::ports::{
    ApplicationCommandContext, PrincipalId, ProjectWorkspaceRepository, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_domain::event::Actor;
use gocode_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use gocode_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use gocode_security::SecretBroker;
use gocode_store::{ProjectWorkspaceStore, store::StoreTransaction};

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn seed_snapshot_backed_conversation(config: &ConfigurationSnapshot) -> SnapshotRow {
    let authority = RuntimeAuthorityId("bootstrap-v17".into());
    let store = StoreTransaction::open(&config.db_path, authority.clone(), available_guard())
        .expect("open the already bootstrapped store");
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000000a1".parse().unwrap();
    let workspace_store = ProjectWorkspaceStore::from_store(store.clone());
    let project_id = ProjectId::from_bytes([0xa2; 16]);
    workspace_store
        .create_project(
            "local-owner",
            CommandId::from_bytes([0xa3; 16]),
            &IdempotencyKey::new("bootstrap-v17-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Bootstrap V17 project".into()).unwrap(),
            ),
        )
        .unwrap();
    workspace_store
        .create_workspace(
            "local-owner",
            CommandId::from_bytes([0xa4; 16]),
            &IdempotencyKey::new("bootstrap-v17-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Bootstrap V17 workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    let context = ApplicationCommandContext {
        command_id: "018f2e3a-7000-7000-8000-0000000000a5".parse().unwrap(),
        idempotency_key: IdempotencyKey::new("bootstrap-v17-conversation").unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("bootstrap-v17-test").unwrap(),
    };
    let conversation_id = "018f2e3a-7000-7000-8000-0000000000a6".parse().unwrap();
    ConversationService::new(store.clone(), store.clone(), authority)
        .create_from_application(
            &context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: context.command_id,
                idempotency_key: context.idempotency_key.clone(),
            },
        )
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(&config.db_path).unwrap();
    let snapshot = connection
        .query_row(
            "SELECT aggregate_type, aggregate_id, codec_version, aggregate_version,
                    event_sequence, head_event_id, head_integrity_digest, projection_bytes,
                    projection_digest, head_global_position, snapshot_integrity_digest
             FROM aggregate_state_snapshots WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| {
                Ok(SnapshotRow {
                    aggregate_type: row.get(0)?,
                    aggregate_id: row.get(1)?,
                    codec_version: row.get(2)?,
                    aggregate_version: row.get(3)?,
                    event_sequence: row.get(4)?,
                    head_event_id: row.get(5)?,
                    head_integrity_digest: row.get(6)?,
                    projection_bytes: row.get(7)?,
                    projection_digest: row.get(8)?,
                    head_global_position: row.get(9)?,
                    snapshot_integrity_digest: row.get(10)?,
                })
            },
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM aggregate_state_snapshots WHERE aggregate_type = ?1 AND aggregate_id = ?2",
            rusqlite::params![snapshot.aggregate_type, snapshot.aggregate_id],
        )
        .unwrap();
    snapshot
}

struct SnapshotRow {
    aggregate_type: i64,
    aggregate_id: Vec<u8>,
    codec_version: i64,
    aggregate_version: i64,
    event_sequence: i64,
    head_event_id: Vec<u8>,
    head_integrity_digest: Vec<u8>,
    projection_bytes: Vec<u8>,
    projection_digest: Vec<u8>,
    head_global_position: i64,
    snapshot_integrity_digest: Vec<u8>,
}

impl SnapshotRow {
    fn restore(self, connection: &rusqlite::Connection) {
        connection
            .execute(
                "INSERT INTO aggregate_state_snapshots
                 (aggregate_type, aggregate_id, codec_version, aggregate_version, event_sequence,
                  head_event_id, head_integrity_digest, projection_bytes, projection_digest,
                  head_global_position, snapshot_integrity_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    self.aggregate_type,
                    self.aggregate_id,
                    self.codec_version,
                    self.aggregate_version,
                    self.event_sequence,
                    self.head_event_id,
                    self.head_integrity_digest,
                    self.projection_bytes,
                    self.projection_digest,
                    self.head_global_position,
                    self.snapshot_integrity_digest,
                ],
            )
            .unwrap();
    }
}

#[test]
fn v17_missing_snapshot_blocks_protected_bootstrap_before_mutations_and_retry_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    secure_runtime_root(directory.path());
    let config = ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(directory.path()));
    drop(
        bootstrap_protected(
            &config,
            FIRST_LAUNCH,
            [0x61; 32],
            &stable(),
            Some(&pending()),
            || Ok(()),
        )
        .unwrap(),
    );
    let snapshot = seed_snapshot_backed_conversation(&config);
    let replay_key = std::path::Path::new(&config.replay_integrity_key_path);
    let local_authority = replay_key.with_file_name("local-session-authority-id");
    let local_authority_before = std::fs::read(&local_authority).unwrap();
    let connection = rusqlite::Connection::open(&config.db_path).unwrap();
    connection
        .execute(
            "DELETE FROM _daemon_info WHERE key = 'local_session_sidecars_v1'",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO _replay_subscriptions
             (session_id, principal_id, session_generation, authority_id, authorization_epoch,
              aggregate_type, aggregate_id, retention_generation, high_water_position, state,
              high_water_ref, created_at)
             VALUES (?1, 'local-owner', 1, ?2, 0, 2, ?3, 0, 0, 'live', ?4, datetime('now'))",
            rusqlite::params![
                [0xb1_u8; 16],
                STABLE_AUTHORITY,
                snapshot.aggregate_id,
                [0xb2_u8; 16],
            ],
        )
        .unwrap();
    drop(connection);
    std::fs::remove_file(replay_key).unwrap();

    let database_path = std::path::PathBuf::from(&config.db_path);
    let runtime_directory = database_path.parent().and_then(Path::parent).unwrap();
    let locks = LockSet::acquire_path(&database_path, runtime_directory).unwrap();
    locks.path_lock.file().set_len(0).unwrap();
    locks.path_lock.file().sync_all().unwrap();
    drop(locks);

    assert!(
        bootstrap_protected(&config, SECOND_LAUNCH, [0x62; 32], &stable(), None, || Ok(
            ()
        ))
        .is_err()
    );
    assert!(!replay_key.exists());
    assert_eq!(
        std::fs::read(&local_authority).unwrap(),
        local_authority_before
    );
    let connection = rusqlite::Connection::open(&config.db_path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "1"
    );
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM _daemon_info WHERE key LIKE 'protected_launch_authority_v1:%'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM _daemon_info WHERE key = 'local_session_sidecars_v1'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    drop(connection);
    let locks = LockSet::acquire_path(&database_path, runtime_directory).unwrap();
    assert!(matches!(
        locks.read_metadata_snapshot().unwrap(),
        gocode_daemon::lock::MetadataSnapshot::Empty
    ));
    drop(locks);

    let connection = rusqlite::Connection::open(&config.db_path).unwrap();
    snapshot.restore(&connection);
    drop(connection);

    let recovered =
        bootstrap_protected(&config, SECOND_LAUNCH, [0x62; 32], &stable(), None, || {
            Ok(())
        })
        .expect("the same unconsumed authority succeeds once the snapshot is repaired");
    assert_eq!(recovered.launch_generation, 2);
}
