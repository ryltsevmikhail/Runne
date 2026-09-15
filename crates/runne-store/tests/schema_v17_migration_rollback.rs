use std::sync::Arc;

use runne_api::CreateConversationInput;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{ApplicationCommandContext, PrincipalId, RuntimeAuthorityId};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::event::Actor;
use runne_domain::id::{ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use runne_domain::message::MessageText;
use runne_security::SecretBroker;
use runne_store::{schema::apply_migrations, store::StoreTransaction};
use rusqlite::{Connection, params};

#[path = "support/v36_receipt_downgrade.rs"]
mod v36_receipt_downgrade;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

fn guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("snapshot-migration").unwrap(),
    }
}

fn v16_fixture(
    label: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    ConversationId,
    TaskRunId,
) {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database = daemon.join(format!("{label}.sqlite"));
    let authority = RuntimeAuthorityId(format!("snapshot-migration-{label}"));
    let store =
        StoreTransaction::open(database.to_str().unwrap(), authority.clone(), guard()).unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000000a1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000000a2".parse().unwrap();
    validated_reopen::seed_canonical_workspace(&store, "local-owner", workspace_id);
    let create = context("018f2e3a-7000-7000-8000-0000000000a3", "migration-create");
    ConversationService::new(store.clone(), store.clone(), authority)
        .create_from_application(
            &create,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create.command_id,
                idempotency_key: create.idempotency_key.clone(),
            },
        )
        .unwrap();
    let text = ConversationTextService::new(
        store.clone(),
        store.clone(),
        store.runtime_authority_id().clone(),
        guard(),
    );
    let started = text
        .begin(
            &context("018f2e3a-7000-7000-8000-0000000000a4", "migration-begin"),
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("migration history").unwrap(),
            },
        )
        .unwrap();
    drop(text);
    drop(store);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER IF EXISTS aggregate_state_snapshots_bind_insert;
         DROP TRIGGER IF EXISTS aggregate_state_snapshots_bind_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_aggregate_state_snapshots_insert;
         DROP TRIGGER IF EXISTS schema_v12_fence_aggregate_state_snapshots_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_aggregate_state_snapshots_delete;
         DROP INDEX IF EXISTS idx_aggregate_state_snapshots_head_position;
         DROP TABLE IF EXISTS aggregate_state_snapshots;
         DROP TABLE IF EXISTS process_output;
         DROP INDEX IF EXISTS idx_process_registry_owner;
         DROP TABLE IF EXISTS process_registry;
         DROP INDEX IF EXISTS idx_approvals_pending;
         DROP TABLE IF EXISTS approvals;
         DROP TABLE IF EXISTS provider_qualification_admission_fences; DROP TABLE IF EXISTS credential_cleanup_recovery_attempts;
         DROP TABLE IF EXISTS provider_online_credential_effect_bindings;
         DROP TABLE IF EXISTS provider_online_dispatch_claim_providers;
         DROP TABLE IF EXISTS provider_online_dispatch_issuance_evidence;
         DROP TABLE IF EXISTS provider_credential_verification_observations;
         DROP TABLE IF EXISTS provider_credential_readiness_observations;
         DROP TABLE IF EXISTS provider_credential_ticket_attempts;
         DROP TABLE IF EXISTS provider_credential_authority_heads;
         DROP TABLE IF EXISTS provider_credential_completion_receipts;
         DROP TABLE IF EXISTS provider_credential_process_attachments;
         DROP TABLE IF EXISTS provider_credential_operations;
         DELETE FROM schema_version WHERE version >= 19;",
    )
        .unwrap();
    v36_receipt_downgrade::restore_v18_receipt(&connection).unwrap();
    (directory, database, conversation_id, started.taskrun_id)
}

fn assert_atomic_v18_rollback(connection: &Connection) {
    assert!(apply_migrations(connection).is_err());
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        18
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'aggregate_state_snapshots%'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

fn malformed_then_repaired(
    label: &str,
    mutate: impl FnOnce(&Connection, ConversationId, TaskRunId) -> Box<dyn FnOnce(&Connection)>,
) {
    let (_directory, database, conversation_id, taskrun_id) = v16_fixture(label);
    let connection = Connection::open(database).unwrap();
    let repair = mutate(&connection, conversation_id, taskrun_id);
    assert_atomic_v18_rollback(&connection);
    repair(&connection);
    apply_migrations(&connection).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM aggregate_state_snapshots",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn v17_backfill_rolls_back_all_streams_then_retries_after_payload_or_digest_repair() {
    malformed_then_repaired("payload", |connection, conversation_id, _| {
        let original: Vec<u8> = connection.query_row("SELECT payload FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()], |row| row.get(0)).unwrap();
        connection.execute("UPDATE events SET payload = x'00' WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()]).unwrap();
        Box::new(move |connection| {
            connection.execute("UPDATE events SET payload = ?1 WHERE aggregate_type = 2 AND aggregate_id = ?2 AND sequence = 1", params![original, conversation_id.as_bytes()]).unwrap();
        })
    });
    malformed_then_repaired("digest", |connection, _, taskrun_id| {
        let original: Vec<u8> = connection.query_row("SELECT integrity_digest FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1", [taskrun_id.as_bytes()], |row| row.get(0)).unwrap();
        connection.execute("UPDATE events SET integrity_digest = zeroblob(32) WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1", [taskrun_id.as_bytes()]).unwrap();
        Box::new(move |connection| {
            connection.execute("UPDATE events SET integrity_digest = ?1 WHERE aggregate_type = 1 AND aggregate_id = ?2 AND sequence = 1", params![original, taskrun_id.as_bytes()]).unwrap();
        })
    });
}

#[test]
fn v17_backfill_rejects_wrong_head_or_profile_without_partial_schema() {
    malformed_then_repaired("head", |connection, conversation_id, _| {
        let original: Vec<u8> = connection.query_row("SELECT last_event_id FROM aggregate_streams WHERE aggregate_type = 2 AND aggregate_id = ?1", [conversation_id.as_bytes()], |row| row.get(0)).unwrap();
        connection.execute("UPDATE aggregate_streams SET last_event_id = zeroblob(16) WHERE aggregate_type = 2 AND aggregate_id = ?1", [conversation_id.as_bytes()]).unwrap();
        Box::new(move |connection| {
            connection.execute("UPDATE aggregate_streams SET last_event_id = ?1 WHERE aggregate_type = 2 AND aggregate_id = ?2", params![original, conversation_id.as_bytes()]).unwrap();
        })
    });
    malformed_then_repaired("profile", |connection, _, taskrun_id| {
        connection.execute("UPDATE events SET integrity_profile = 2 WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1", [taskrun_id.as_bytes()]).unwrap();
        Box::new(move |connection| {
            connection.execute("UPDATE events SET integrity_profile = 1 WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1", [taskrun_id.as_bytes()]).unwrap();
        })
    });
}

#[test]
fn v17_backfill_rejects_pruned_prefix_interior_gap_wrong_correlation_and_oversize() {
    malformed_then_repaired("prefix", |connection, conversation_id, _| {
        connection
            .execute_batch(
                "CREATE TEMP TABLE snapshot_backup AS
             SELECT * FROM events WHERE aggregate_type = 2 AND sequence = 1;",
            )
            .unwrap();
        connection.execute("DELETE FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()]).unwrap();
        Box::new(|connection| {
            connection
                .execute_batch(
                    "INSERT INTO events SELECT * FROM snapshot_backup; DROP TABLE snapshot_backup;",
                )
                .unwrap();
        })
    });
    malformed_then_repaired("interior", |connection, _, taskrun_id| {
        connection
            .execute_batch(
                "CREATE TEMP TABLE snapshot_backup AS
             SELECT * FROM events WHERE aggregate_type = 1 AND sequence = 2;",
            )
            .unwrap();
        connection.execute("DELETE FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 2", [taskrun_id.as_bytes()]).unwrap();
        Box::new(|connection| {
            connection
                .execute_batch(
                    "INSERT INTO events SELECT * FROM snapshot_backup; DROP TABLE snapshot_backup;",
                )
                .unwrap();
        })
    });
    malformed_then_repaired("correlation", |connection, _, taskrun_id| {
        connection.execute("UPDATE events SET correlation_type = 2 WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1", [taskrun_id.as_bytes()]).unwrap();
        Box::new(move |connection| {
            connection.execute("UPDATE events SET correlation_type = 1 WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1", [taskrun_id.as_bytes()]).unwrap();
        })
    });
    malformed_then_repaired("oversize", |connection, conversation_id, _| {
        let original: Vec<u8> = connection.query_row("SELECT payload FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()], |row| row.get(0)).unwrap();
        connection.execute("UPDATE events SET payload = zeroblob(524289) WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()]).unwrap();
        Box::new(move |connection| {
            connection.execute("UPDATE events SET payload = ?1 WHERE aggregate_type = 2 AND aggregate_id = ?2 AND sequence = 1", params![original, conversation_id.as_bytes()]).unwrap();
        })
    });
}

#[test]
fn v17_backfill_rejects_noncanonical_first_and_later_causation_then_repairs() {
    malformed_then_repaired("first-causation", |connection, conversation_id, _| {
        let event_id: Vec<u8> = connection.query_row("SELECT event_id FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()], |row| row.get(0)).unwrap();
        connection.execute("UPDATE events SET causation_id = ?1 WHERE aggregate_type = 2 AND aggregate_id = ?2 AND sequence = 1", params![event_id, conversation_id.as_bytes()]).unwrap();
        Box::new(move |connection| {
            connection.execute("UPDATE events SET causation_id = NULL WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()]).unwrap();
        })
    });
    malformed_then_repaired("skipped-causation", |connection, _, taskrun_id| {
        let original: Vec<u8> = connection.query_row("SELECT causation_id FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 3", [taskrun_id.as_bytes()], |row| row.get(0)).unwrap();
        let first: Vec<u8> = connection.query_row("SELECT event_id FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1", [taskrun_id.as_bytes()], |row| row.get(0)).unwrap();
        connection.execute("UPDATE events SET causation_id = ?1 WHERE aggregate_type = 1 AND aggregate_id = ?2 AND sequence = 3", params![first, taskrun_id.as_bytes()]).unwrap();
        Box::new(move |connection| {
            connection.execute("UPDATE events SET causation_id = ?1 WHERE aggregate_type = 1 AND aggregate_id = ?2 AND sequence = 3", params![original, taskrun_id.as_bytes()]).unwrap();
        })
    });
}
