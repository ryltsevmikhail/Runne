use std::sync::Arc;

use gocode_api::CreateConversationInput;
use gocode_application::commands::BeginConversationTextInput;
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::ConversationTextService;
use gocode_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_domain::event::Actor;
use gocode_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
use gocode_domain::message::MessageText;
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;
use rusqlite::Connection;

#[path = "support/validated_reopen.rs"]
mod validated_reopen;

type DurableState = (i64, i64, i64, i64, Vec<(i64, Vec<u8>)>);

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("snapshot-rollback").unwrap(),
    }
}

fn durable_state(connection: &Connection) -> DurableState {
    let snapshots = connection
        .prepare(
            "SELECT aggregate_type, snapshot_integrity_digest
             FROM aggregate_state_snapshots ORDER BY aggregate_type, aggregate_id",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    (
        connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM aggregate_streams", [], |row| {
                row.get(0)
            })
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM command_receipts", [], |row| {
                row.get(0)
            })
            .unwrap(),
        connection
            .query_row(
                "SELECT COUNT(*) FROM task_run_workspace_lineage",
                [],
                |row| row.get(0),
            )
            .unwrap(),
        snapshots,
    )
}

#[test]
fn snapshot_failure_rolls_back_text_events_heads_receipt_lineage_and_both_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("snapshot-write-rollback.sqlite");
    let authority = RuntimeAuthorityId("snapshot-write-rollback".into());
    let store = StoreTransaction::open(
        database.to_str().unwrap(),
        authority.clone(),
        available_guard(),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000091".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000092".parse().unwrap();
    validated_reopen::seed_canonical_workspace(&store, "local-owner", workspace_id);
    let create = context("018f2e3a-7000-7000-8000-000000000093", "snapshot-create");
    ConversationService::new(store.clone(), store.clone(), authority.clone())
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
    let connection = Connection::open(&database).unwrap();
    let before = durable_state(&connection);
    let position_before: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(global_position), 0) FROM events",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER test_reject_snapshot_update
             BEFORE UPDATE ON aggregate_state_snapshots
             BEGIN SELECT RAISE(ABORT, 'snapshot failpoint'); END;",
        )
        .unwrap();
    let text =
        ConversationTextService::new(store.clone(), store.clone(), authority, available_guard());
    let begin = text.begin(
        &context("018f2e3a-7000-7000-8000-000000000094", "snapshot-begin"),
        BeginConversationTextInput {
            conversation_id,
            expected_version: 1,
            text: MessageText::new("atomic snapshot").unwrap(),
        },
    );
    assert!(begin.is_err());
    connection
        .execute_batch("DROP TRIGGER test_reject_snapshot_update;")
        .unwrap();
    assert_eq!(durable_state(&connection), before);
    assert_eq!(
        connection
            .query_row(
                "SELECT COALESCE(MAX(global_position), 0) FROM events",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        position_before,
    );
    assert_eq!(
        store
            .load_conversation(conversation_id)
            .unwrap()
            .current_version,
        1
    );
}
