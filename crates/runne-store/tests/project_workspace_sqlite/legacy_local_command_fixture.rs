#![allow(dead_code)]

use std::path::Path;

use runne_api::{ApiPrincipalId, ApprovalCreateCommand, ApprovalRequestHostPort};
use runne_application::{conversation_service::ConversationService, ports::EventStore};
use runne_domain::id::{ApprovalId, ConversationId, InvocationId, TaskRunId, WorkspaceId};
use runne_domain::task_run::{TaskRunExecutable, TaskRunInput, TaskRunLocalCommand};
use runne_store::{
    ProjectWorkspaceStore, schema::ManagedConnection, store::LocalCommandApprovalBinding,
};
use rusqlite::{Connection, params};

use super::support::*;

#[path = "../support/x2_historical_schema_fixture/mod.rs"]
mod historical_schema;

pub struct PreparedLegacyLocalCommand {
    pub database: Database,
    pub taskrun_id: TaskRunId,
    pub local: TaskRunLocalCommand,
    pub approval_id: ApprovalId,
    pub binding: LocalCommandApprovalBinding,
}

#[derive(Clone, Copy)]
struct LegacyFixtureSeed<'a> {
    staged_state: &'a str,
    include_binding: bool,
    include_submit_receipt: bool,
}

impl LegacyFixtureSeed<'static> {
    const fn pending() -> Self {
        Self {
            staged_state: "approval_pending",
            include_binding: true,
            include_submit_receipt: true,
        }
    }
}

pub async fn prepare(
    name: &str,
    seed: u8,
    approval_tail: u8,
    executable_digest: [u8; 32],
    admitted_root_identity: [u8; 32],
) -> PreparedLegacyLocalCommand {
    prepare_inner(
        name,
        seed,
        approval_tail,
        executable_digest,
        admitted_root_identity,
        false,
        LegacyFixtureSeed::pending(),
    )
    .await
    .expect("valid historical fixture migrates")
}

pub async fn prepare_with_node_authority(
    name: &str,
    seed: u8,
    approval_tail: u8,
    executable_digest: [u8; 32],
    admitted_root_identity: [u8; 32],
) -> PreparedLegacyLocalCommand {
    prepare_inner(
        name,
        seed,
        approval_tail,
        executable_digest,
        admitted_root_identity,
        true,
        LegacyFixtureSeed::pending(),
    )
    .await
    .expect("valid historical fixture migrates")
}

pub async fn migration_rejects_fixture(
    name: &str,
    seed: u8,
    approval_tail: u8,
    state: &str,
    include_binding: bool,
    include_submit_receipt: bool,
) -> bool {
    prepare_inner(
        name,
        seed,
        approval_tail,
        [0x31; 32],
        [0x32; 32],
        false,
        LegacyFixtureSeed {
            staged_state: state,
            include_binding,
            include_submit_receipt,
        },
    )
    .await
    .is_err()
}

async fn prepare_inner(
    name: &str,
    seed: u8,
    approval_tail: u8,
    executable_digest: [u8; 32],
    admitted_root_identity: [u8; 32],
    use_node_authority: bool,
    fixture_seed: LegacyFixtureSeed<'_>,
) -> rusqlite::Result<PreparedLegacyLocalCommand> {
    let donor = Database::new(&format!("{name}-donor"));
    let repository = donor.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(seed).into_bytes());
    ConversationService::new(donor.store.clone(), donor.store.clone(), authority())
        .create_from_application(
            &task_context(seed, "legacy-local-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(seed),
                idempotency_key: key("legacy-local-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let local = local_command();
    let (submit_store, submit_authority) = if use_node_authority {
        let connection = donor.connection();
        let authority_bytes: Vec<u8> = connection
            .query_row(
                "SELECT authority_id FROM _authority WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let node_authority = runne_application::ports::RuntimeAuthorityId(
            uuid::Uuid::from_bytes(authority_bytes.try_into().unwrap()).to_string(),
        );
        drop(connection);
        (
            crate::validated_reopen::reopen_store(
                donor.file.path(),
                donor.identity,
                node_authority.clone(),
                guard(),
            )
            .unwrap(),
            node_authority,
        )
    } else {
        (donor.store.clone(), authority())
    };
    let migration_authority = submit_authority.clone();
    let submitter = runne_application::service::TaskRunService::new(
        submit_store.clone(),
        submit_store.clone(),
        submit_store,
        submit_authority,
    );
    let outcome = submitter
        .submit_task_run(
            &task_context(seed + 1, "legacy-local-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: TaskRunInput::new("description".into())
                    .unwrap()
                    .with_local_command(local.clone())
                    .unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome
    else {
        panic!("submitted local TaskRun")
    };
    let approval_id = ApprovalId::from_bytes(command(approval_tail).into_bytes());
    let binding = LocalCommandApprovalBinding {
        command_digest: local.intent_digest(),
        executable_digest,
        workspace_version: 1,
        admitted_root_version: 1,
        admitted_root_identity,
        trust_epoch: 1,
        trust_revision: 1,
        source_policy_version: 2,
        command_policy_version: 1,
        approval_id: *approval_id.as_bytes(),
    };
    create_pending_approval(&repository, taskrun_id, &local, approval_id).await;
    let database = migrate_pending_seed(
        &donor,
        taskrun_id,
        approval_id,
        binding,
        name,
        fixture_seed,
        migration_authority,
    )?;
    Ok(PreparedLegacyLocalCommand {
        database,
        taskrun_id,
        local,
        approval_id,
        binding,
    })
}

pub async fn create_pending_approval(
    repository: &ProjectWorkspaceStore,
    taskrun_id: TaskRunId,
    local: &TaskRunLocalCommand,
    approval_id: ApprovalId,
) {
    let request = ApprovalCreateCommand::new(
        approval_id,
        taskrun_id,
        None,
        InvocationId::from_bytes(command(approval_id.as_bytes()[15].wrapping_add(1)).into_bytes()),
        ApiPrincipalId::new("owner").unwrap(),
        "local_command.execute",
        format!(
            "taskrun:{taskrun_id}:workspace:{}",
            WorkspaceId::from_bytes(WORKSPACE)
        ),
        local.intent_digest(),
        2,
        1,
        i64::MAX,
        "reviewed local command",
    )
    .unwrap();
    repository.create_pending_approval(request).await.unwrap();
}

pub fn migrate_pending(
    donor: &Database,
    taskrun_id: TaskRunId,
    approval_id: ApprovalId,
    binding: LocalCommandApprovalBinding,
    name: &str,
) -> Database {
    migrate_pending_seed(
        donor,
        taskrun_id,
        approval_id,
        binding,
        name,
        LegacyFixtureSeed::pending(),
        authority(),
    )
    .expect("valid historical fixture migrates")
}

fn migrate_pending_seed(
    donor: &Database,
    taskrun_id: TaskRunId,
    approval_id: ApprovalId,
    binding: LocalCommandApprovalBinding,
    name: &str,
    fixture_seed: LegacyFixtureSeed<'_>,
    runtime_authority: runne_application::ports::RuntimeAuthorityId,
) -> rusqlite::Result<Database> {
    let donor_connection = donor.connection();
    assert_eq!(permission_route(&donor_connection, taskrun_id), (2, 3, 68));
    assert_permission_capture_rows_empty(&donor_connection);

    let file = crate::validated_reopen::ValidatedTestDatabase::new(&format!("{name}-legacy-v67"));
    let destination = runne_store::schema::open_managed_connection(
        file.as_path(),
        runne_store::schema::ConnectionMode::Writer,
    )
    .unwrap();
    runne_store::schema::apply_migrations_through_v67_for_test(&destination).unwrap();
    historical_schema::copy_conversation_and_taskrun_history(
        &destination,
        donor.file.as_path(),
        &conversation_id(&donor_connection, taskrun_id),
        &taskrun_id.as_bytes()[..],
    )
    .unwrap();
    copy_legacy_support(
        &destination,
        donor.file.as_path(),
        taskrun_id,
        approval_id,
        binding,
        fixture_seed,
    )?;

    let actual_staged_state: String = destination.query_row(
        "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
        [taskrun_id.as_bytes()],
        |row| row.get(0),
    )?;
    assert_eq!(actual_staged_state, fixture_seed.staged_state);
    assert_eq!(schema_version(&destination), 67);
    let identity = crate::validated_reopen::read_main_database_identity(&destination).unwrap();
    runne_store::schema::apply_migrations(&destination)?;
    runne_store::schema::readiness_from_managed(&destination)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    assert_eq!(permission_route(&destination, taskrun_id), (1, 1, 68));
    assert_permission_capture_rows_empty(&destination);
    drop(destination);

    assert_eq!(permission_route(&donor_connection, taskrun_id), (2, 3, 68));
    drop(donor_connection);
    let store =
        crate::validated_reopen::reopen_store(file.path(), identity, runtime_authority, guard())
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
    assert_eq!(store.load_task_run(taskrun_id).unwrap().current_version, 2);
    Ok(Database {
        file,
        identity,
        store,
    })
}

fn local_command() -> TaskRunLocalCommand {
    TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap()
}

fn copy_legacy_support(
    destination: &Connection,
    source_path: &Path,
    taskrun_id: TaskRunId,
    approval_id: ApprovalId,
    binding: LocalCommandApprovalBinding,
    fixture_seed: LegacyFixtureSeed<'_>,
) -> rusqlite::Result<()> {
    destination.execute_batch("PRAGMA foreign_keys=OFF;")?;
    let result: rusqlite::Result<()> = (|| {
        destination.execute(
            "ATTACH DATABASE ?1 AS x2_legacy_source",
            [source_path.to_str().ok_or(rusqlite::Error::InvalidQuery)?],
        )?;
        for table in ["_authority", "projects", "workspaces"] {
            destination.execute_batch(&format!(
                "INSERT INTO {table} SELECT * FROM x2_legacy_source.{table};"
            ))?;
        }
        let counter_rows = destination.execute(
            "UPDATE event_log_state SET next_global_position=(
                 SELECT next_global_position FROM x2_legacy_source.event_log_state WHERE singleton=1
             ) WHERE singleton=1",
            [],
        )?;
        if counter_rows != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        for table in [
            "workspace_identity_history",
            "project_workspace_command_receipts",
            "task_run_workspace_lineage",
            "conversation_context_scope",
        ] {
            destination.execute_batch(&format!(
                "INSERT INTO {table} SELECT * FROM x2_legacy_source.{table};"
            ))?;
        }
        destination.execute(
            "INSERT INTO command_receipts SELECT * FROM x2_legacy_source.command_receipts
             WHERE ?1 OR command_id!=(SELECT command_id FROM x2_legacy_source.events
                 WHERE aggregate_type=1 AND aggregate_id=?2 AND sequence=1)",
            params![fixture_seed.include_submit_receipt, taskrun_id.as_bytes()],
        )?;
        destination.execute(
            "INSERT INTO aggregate_state_snapshots(
                 aggregate_type,aggregate_id,codec_version,aggregate_version,event_sequence,
                 head_event_id,head_integrity_digest,projection_bytes,projection_digest,
                 promotion_codec_version,promotion_projection_bytes,promotion_projection_digest,
                 head_global_position,snapshot_integrity_digest
             )
             SELECT snapshot.aggregate_type,snapshot.aggregate_id,snapshot.codec_version,
                    snapshot.aggregate_version,snapshot.event_sequence,snapshot.head_event_id,
                    snapshot.head_integrity_digest,snapshot.projection_bytes,snapshot.projection_digest,
                    snapshot.promotion_codec_version,snapshot.promotion_projection_bytes,
                    snapshot.promotion_projection_digest,snapshot.head_global_position,
                    snapshot.snapshot_integrity_digest
             FROM x2_legacy_source.aggregate_state_snapshots AS snapshot
             JOIN main.aggregate_streams AS destination_stream
               ON destination_stream.aggregate_type=snapshot.aggregate_type
              AND destination_stream.aggregate_id=snapshot.aggregate_id",
            [],
        )?;
        let (stream_count, snapshot_count, missing_snapshot): (i64, i64, bool) = destination
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type IN (1,2)),
                    (SELECT COUNT(*) FROM aggregate_state_snapshots),
                    EXISTS(
                        SELECT 1 FROM aggregate_streams AS stream
                        LEFT JOIN aggregate_state_snapshots AS snapshot
                          ON snapshot.aggregate_type=stream.aggregate_type
                         AND snapshot.aggregate_id=stream.aggregate_id
                        WHERE stream.aggregate_type IN (1,2)
                          AND snapshot.aggregate_id IS NULL
                    )",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        assert_eq!(
            stream_count, 2,
            "fixture has conversation and TaskRun streams"
        );
        assert_eq!(snapshot_count, stream_count);
        assert!(!missing_snapshot, "every supported stream has a snapshot");
        destination.execute(
            "INSERT INTO _daemon_info(key,value)
             SELECT key,value FROM x2_legacy_source._daemon_info
             WHERE key='event_log_lineage_id'",
            [],
        )?;
        destination.execute(
            "INSERT INTO approvals SELECT * FROM x2_legacy_source.approvals WHERE approval_id=?1",
            [approval_id.to_string()],
        )?;
        if fixture_seed.include_binding {
            destination.execute(
                "INSERT INTO taskrun_local_command_attempts(
                 taskrun_id,conversation_id,workspace_id,command_digest,attempt_id,node_id,
                 node_epoch,fence,executable_digest,workspace_version,admitted_root_version,
                 admitted_root_identity,trust_epoch,trust_revision,source_policy_version,
                 command_policy_version,approval_id,managed_area_identity,state,stdout,stderr,
                 exit_code,updated_at
             )
             SELECT taskrun_id,conversation_id,workspace_id,command_digest,NULL,NULL,NULL,NULL,
                    ?2,1,1,?3,1,1,2,1,?4,NULL,?5,stdout,stderr,NULL,updated_at
             FROM x2_legacy_source.taskrun_local_command_attempts WHERE taskrun_id=?1",
                params![
                    taskrun_id.as_bytes(),
                    binding.executable_digest.as_slice(),
                    binding.admitted_root_identity.as_slice(),
                    binding.approval_id.as_slice(),
                    fixture_seed.staged_state,
                ],
            )?;
        } else {
            destination.execute(
                "INSERT INTO taskrun_local_command_attempts(
                 taskrun_id,conversation_id,workspace_id,command_digest,attempt_id,node_id,
                 node_epoch,fence,executable_digest,workspace_version,admitted_root_version,
                 admitted_root_identity,trust_epoch,trust_revision,source_policy_version,
                 command_policy_version,approval_id,managed_area_identity,state,stdout,stderr,
                 exit_code,updated_at
             )
             SELECT taskrun_id,conversation_id,workspace_id,command_digest,NULL,NULL,NULL,NULL,
                    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?2,stdout,stderr,NULL,updated_at
             FROM x2_legacy_source.taskrun_local_command_attempts WHERE taskrun_id=?1",
                params![taskrun_id.as_bytes(), fixture_seed.staged_state],
            )?;
        }
        Ok(())
    })();
    let detach = destination.execute_batch("DETACH DATABASE x2_legacy_source;");
    let restore_foreign_keys = destination.execute_batch("PRAGMA foreign_keys=ON;");
    result?;
    detach?;
    restore_foreign_keys
}

fn conversation_id(connection: &ManagedConnection, taskrun_id: TaskRunId) -> Vec<u8> {
    connection
        .query_row(
            "SELECT conversation_id FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap()
}

fn permission_route(connection: &Connection, taskrun_id: TaskRunId) -> (i64, i64, i64) {
    connection
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes
             WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

fn assert_permission_capture_rows_empty(connection: &Connection) {
    let count: i64 = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM x2_permission_bindings)
                  +(SELECT COUNT(*) FROM x2_permission_human)
                  +(SELECT COUNT(*) FROM x2_permission_admission)
                  +(SELECT COUNT(*) FROM x2_permission_spent)
                  +(SELECT COUNT(*) FROM x2_permission_stop)
                  +(SELECT COUNT(*) FROM x2_permission_terminal)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "historical fixture has no compiled permission capture"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn historical_denied_without_release_receipt_is_rejected() {
    assert!(
        migration_rejects_fixture(
            "legacy-denied-without-release",
            0xa1,
            0xa2,
            "denied",
            true,
            true
        )
        .await
    );
}

#[tokio::test(flavor = "current_thread")]
async fn historical_approval_pending_without_full_binding_is_rejected() {
    assert!(
        migration_rejects_fixture(
            "legacy-approval-missing-binding",
            0xa3,
            0xa4,
            "approval_pending",
            false,
            true,
        )
        .await
    );
}

#[tokio::test(flavor = "current_thread")]
async fn historical_local_command_without_submit_receipt_is_rejected() {
    assert!(
        migration_rejects_fixture(
            "legacy-approval-missing-origin",
            0xa5,
            0xa6,
            "approval_pending",
            true,
            false,
        )
        .await
    );
}

fn schema_version(connection: &Connection) -> i64 {
    connection
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap()
}
