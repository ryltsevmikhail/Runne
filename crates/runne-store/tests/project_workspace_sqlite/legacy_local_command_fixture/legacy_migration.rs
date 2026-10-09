use std::path::Path;

use runne_application::ports::EventStore;
use runne_domain::id::{ApprovalId, TaskRunId};
use runne_store::{schema::ManagedConnection, store::LocalCommandApprovalBinding};
use rusqlite::{Connection, params};

use super::super::support::*;
use super::historical_schema;
use super::schema_version;
use super::seed::LegacyFixtureSeed;

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

pub(super) fn migrate_pending_seed(
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
