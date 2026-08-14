use std::path::{Path, PathBuf};

use gocode_application::commands::CommandOutcome;
use gocode_application::ports::{
    AggregateScope, IdempotencyScope, OperationTag, PrincipalId, RuntimeAuthorityId,
    TextGenerationPhase, TextGenerationReceipt,
};
use gocode_domain::id::{AttemptId, CommandId, ConversationId, MessageId, TaskRunId, WorkspaceId};
use gocode_store::{
    codec::{CommandOutcomeCodec, IdempotencyScopeCodec, StoreCodec, TextGenerationReceiptCodec},
    provider::SqliteProviderExecutionStore,
    schema::{
        CURRENT_SCHEMA_VERSION, apply_migrations, apply_migrations_through_v15_for_test,
        preflight_existing_file,
    },
};
use rusqlite::{Connection, params};

fn released_v15_database() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("released-v15.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations_through_v15_for_test(&connection).unwrap();
    seed_origin_receipts(&connection);
    drop(connection);
    (directory, path)
}

fn seed_origin_receipts(connection: &Connection) {
    let workspace: WorkspaceId = "018f47a2-4f8c-7b52-8c35-7a3a14c2da01".parse().unwrap();
    let conversation: ConversationId = "018f47a2-4f8c-7b52-8c35-7a3a14c2da02".parse().unwrap();
    let direct_task: TaskRunId = "018f47a2-4f8c-7b52-8c35-7a3a14c2da03".parse().unwrap();
    let text_task: TaskRunId = "018f47a2-4f8c-7b52-8c35-7a3a14c2da04".parse().unwrap();
    for (task, version) in [(direct_task, 1_i64), (text_task, 4_i64)] {
        connection
            .execute(
                "INSERT INTO aggregate_streams
                 (aggregate_type, aggregate_id, current_version, created_at)
                 VALUES (1, ?1, ?2, 1)",
                params![task.as_bytes(), version],
            )
            .unwrap();
    }
    let direct_scope = IdempotencyScope {
        runtime_authority_id: RuntimeAuthorityId("released-v15".into()),
        principal_id: PrincipalId("owner".into()),
        operation: OperationTag::CreateTaskRun,
        aggregate_scope: AggregateScope::NewTaskRun {
            conversation_id: conversation,
            workspace_id: workspace,
        },
    };
    insert_receipt(
        connection,
        "018f47a2-4f8c-7b52-8c35-7a3a14c2da05".parse().unwrap(),
        "direct",
        IdempotencyScopeCodec.encode(&direct_scope).unwrap(),
        CommandOutcomeCodec
            .encode(&CommandOutcome::TaskRunCreated {
                taskrun_id: direct_task,
                new_version: 1,
            })
            .unwrap(),
    );
    let text_scope = IdempotencyScope {
        runtime_authority_id: RuntimeAuthorityId("released-v15".into()),
        principal_id: PrincipalId("owner".into()),
        operation: OperationTag::GenerateConversationText,
        aggregate_scope: AggregateScope::ExistingConversation {
            conversation_id: conversation,
        },
    };
    let text = TextGenerationReceipt {
        phase: TextGenerationPhase::Started,
        conversation_id: conversation,
        workspace_id: workspace,
        taskrun_id: text_task,
        attempt_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2da06"
            .parse::<AttemptId>()
            .unwrap(),
        user_message_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2da07"
            .parse::<MessageId>()
            .unwrap(),
        assistant_message_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2da08"
            .parse::<MessageId>()
            .unwrap(),
        conversation_version: 2,
        taskrun_version: 4,
    };
    insert_receipt(
        connection,
        "018f47a2-4f8c-7b52-8c35-7a3a14c2da09".parse().unwrap(),
        "text",
        IdempotencyScopeCodec.encode(&text_scope).unwrap(),
        TextGenerationReceiptCodec.encode(&text).unwrap(),
    );
}

fn insert_receipt(
    connection: &Connection,
    command: CommandId,
    key: &str,
    scope: Vec<u8>,
    outcome: Vec<u8>,
) {
    connection.execute("INSERT INTO command_receipts
        (command_id, idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome, committed_at)
        VALUES (?1, ?2, ?3, zeroblob(32), ?4, 1)", params![command.as_bytes(), scope, key.as_bytes(), outcome]).unwrap();
}

fn replace_table_ddl(path: &Path, table: &str, old: &str, new: &str) {
    let connection = Connection::open(path).unwrap();
    let ddl: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .unwrap();
    assert!(ddl.contains(old), "fixture did not find {old:?} in {table}");
    let cookie: i64 = connection
        .pragma_query_value(None, "schema_version", |row| row.get(0))
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema = ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_master SET sql = replace(sql, ?2, ?3)
             WHERE type = 'table' AND name = ?1",
            params![table, old, new],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema = OFF;")
        .unwrap();
    connection
        .execute_batch(&format!("PRAGMA schema_version = {};", cookie + 1))
        .unwrap();
}

#[test]
fn preflight_rejects_v15_with_tampered_inherited_v14_activation_binding() {
    let (_directory, path) = released_v15_database();
    replace_table_ddl(
        &path,
        "provider_execution_admissions",
        "activation_binding_kind TEXT NOT NULL DEFAULT 'legacy_unbound'\n    CHECK(activation_binding_kind IN ('legacy_unbound', 'protected_v2', 'external_owner_private'))",
        "activation_binding_kind TEXT NOT NULL DEFAULT 'legacy_unbound'",
    );
    assert!(preflight_existing_file(&path).is_err());
    assert!(SqliteProviderExecutionStore::open(&path).is_err());
}

#[test]
fn v17_rejects_released_v15_fixture_without_complete_replay_histories() {
    let (_directory, path) = released_v15_database();
    let released = Connection::open(&path).unwrap();
    assert_eq!(
        released
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        15
    );
    assert!(
        !released
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'task_run_workspace_lineage')",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
    );
    drop(released);
    preflight_existing_file(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    assert!(apply_migrations(&connection).is_err());
    assert_eq!(CURRENT_SCHEMA_VERSION, 18);
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        16
    );
    assert!(connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'provider_effect_starts')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap());
    let lineage = connection
        .prepare("SELECT classification, origin_operation FROM task_run_workspace_lineage ORDER BY origin_operation")
        .unwrap()
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        lineage,
        vec![("legacy_unbound".into(), 1), ("legacy_unbound".into(), 18)]
    );
    let history = connection
        .query_row(
            "SELECT classification, project_id, principal_id
             FROM workspace_identity_history",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(history, ("legacy_unbound".into(), None, None));
}

#[test]
fn corrupt_v15_origin_rolls_back_v16_atomically() {
    let (_directory, path) = released_v15_database();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("UPDATE command_receipts SET command_outcome = x'00' WHERE idempotency_key = x'74657874'", [])
        .unwrap();
    assert!(apply_migrations(&connection).is_err());
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        15
    );
    assert!(!connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'task_run_workspace_lineage')", [], |row| row.get::<_, bool>(0)).unwrap());
    assert!(!connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'workspace_identity_history')", [], |row| row.get::<_, bool>(0)).unwrap());
}

#[test]
fn preflight_rejects_tampered_v16_global_command_trigger() {
    let (_directory, path) = released_v15_database();
    let connection = Connection::open(&path).unwrap();
    assert!(apply_migrations(&connection).is_err());
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        16,
    );
    connection
        .execute_batch("DROP TRIGGER global_command_id_from_command_receipts")
        .unwrap();
    drop(connection);
    assert!(preflight_existing_file(&path).is_err());
}
