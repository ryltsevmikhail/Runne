use std::path::Path;
use std::time::Duration;

use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The restart phase carries the workspace, database, markers, and restart handles together."
)]
pub(super) async fn run(
    workspace_id: runne_runtime_client::CanonicalId,
    database: &Path,
    marker: &Path,
    detached: &Path,
    permission_before: runne_api::PermissionModeStatusV1,
    task_run_id: runne_runtime_client::CanonicalId,
    task_bytes: [u8; 16],
    mut restarted: runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    restarted_client: runne_runtime_client::AuthenticatedRuntimeClient,
) -> (
    runne_application::ports::RuntimeAuthorityId,
    runne_store::store::StoreTransaction,
    [u8; 16],
    i64,
    u64,
) {
    let permission_after = restarted_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected permission mode after restart");
    assert_eq!(
        permission_after.selected_mode,
        permission_before.selected_mode
    );
    assert_eq!(
        permission_after.authorization_revision,
        permission_before.authorization_revision
    );
    let outcome_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = restarted_client
            .get_task_run(task_run_id)
            .await
            .expect("read recovered same TaskRun ID");
        if snapshot.state() == runne_runtime_client::TaskRunState::Unrecoverable {
            break;
        }
        assert!(
            tokio::time::Instant::now() < outcome_deadline,
            "restart did not reconcile old effect: {:?}",
            snapshot.state()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let effects = restarted_client
        .get_task_run_effects(task_run_id)
        .await
        .expect("read recovered local effect projection");
    let local = effects
        .local_command()
        .expect("recovered task retains its local-command effect");
    assert_eq!(
        local.outcome(),
        runne_runtime_client::LocalExecutionOutcome::OutcomeUnknown
    );
    assert_eq!(
        local.stop(),
        runne_runtime_client::LocalStopEvidence::Confirmed
    );
    assert_eq!(local.exit_code(), None);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        "run\n",
        "recovery observes and stops the old cgroup without relaunching"
    );
    assert!(
        std::fs::read_to_string(detached).is_ok(),
        "the detached child entered the pre-crash body"
    );
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open recovered event log read-only");
    let (bytes, attempt_state, exit_code): (Vec<u8>, String, Option<i32>) = connection
        .query_row(
            "SELECT managed_area_identity,state,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("recovered attempt area identity");
    assert_eq!(attempt_state, "outcome_unknown");
    assert_eq!(exit_code, None, "restart records no invented process exit");
    let attempt_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("count recovered local attempts");
    assert_eq!(attempt_count, 1, "crash recovery preserves one attempt");
    let durable_stop_proof: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM taskrun_local_command_attempts a
             JOIN taskrun_local_command_stop_receipts s
               ON s.taskrun_id=a.taskrun_id AND s.attempt_id=a.attempt_id AND s.fence=a.fence
             JOIN taskrun_terminal_settlement_receipts t
               ON t.taskrun_id=s.taskrun_id AND t.fence=s.fence
                  AND t.attempt_id=s.attempt_id AND t.node_id=s.historic_node_id
                  AND t.node_epoch=s.historic_node_epoch
                  AND t.terminal_event_id=s.terminal_event_id
                  AND t.terminal_version=s.terminal_version
             JOIN taskrun_assignment_occupations o
               ON o.taskrun_id=s.taskrun_id AND o.fence=s.fence
             JOIN events terminal ON terminal.event_id=s.terminal_event_id
               AND terminal.aggregate_id=s.taskrun_id AND terminal.sequence=s.terminal_version
             WHERE a.taskrun_id=?1 AND a.state='outcome_unknown' AND a.exit_code IS NULL
               AND s.stop_kind='outcome_unknown' AND s.proof_node_id=s.historic_node_id
               AND s.proof_node_epoch>a.node_epoch
               AND s.managed_area_identity=a.managed_area_identity
               AND s.command_digest=a.command_digest
               AND o.state='released' AND o.release_event_id=s.terminal_event_id
               AND terminal.causation_id IS NOT NULL",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("read recovered native stop proof");
    assert_eq!(
        durable_stop_proof, 1,
        "exact unknown-stop and released receipts persist"
    );
    let authority_id = runne_store::schema::read_authority_id(&connection)
        .expect("read recovered runtime authority")
        .expect("runtime authority is present");
    let lineage_id = runne_store::schema::read_event_log_lineage_id(&connection)
        .expect("read recovered event-log lineage")
        .expect("event-log lineage is present");
    let mut node_statement = connection
        .prepare("SELECT node_id,launch_generation FROM execution_nodes ORDER BY node_id")
        .expect("prepare current execution-node read");
    let current_nodes = node_statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })
        .expect("read current execution nodes")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect current execution nodes");
    drop(node_statement);
    assert_eq!(
        current_nodes.len(),
        1,
        "one current runtime node is registered"
    );
    let (node_id_bytes, node_epoch) = current_nodes.into_iter().next().unwrap();
    let node_id: [u8; 16] = node_id_bytes
        .try_into()
        .expect("current node UUID has sixteen bytes");
    assert!(node_epoch > 0, "current execution-node epoch is positive");
    let (terminal_version, current_version): (i64, i64) = connection
        .query_row(
            "SELECT terminal.terminal_version,stream.current_version
             FROM taskrun_terminal_settlement_receipts terminal
             JOIN aggregate_streams stream ON stream.aggregate_type=1
               AND stream.aggregate_id=terminal.taskrun_id
             WHERE terminal.taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read recovered terminal version and stream head");
    assert_eq!(terminal_version, current_version);
    let terminal_version = u64::try_from(terminal_version).expect("positive terminal version");
    let identity = runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&bytes)
        .expect("persisted managed area identity");
    let identity_bytes = identity.to_bytes();
    let binding = runne_platform::process_managed_area::ManagedAreaBinding::new(
        task_bytes,
        identity_bytes[68..84].try_into().unwrap(),
        identity_bytes[84..100].try_into().unwrap(),
    )
    .expect("persisted attempt binding");
    let root = runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
        .expect("delegated recovery root");
    assert!(
        root.reopen_area(identity, binding).is_err(),
        "recovery cleaned the exact empty area"
    );
    restarted.stop().expect("stop restarted protected daemon");
    drop(restarted_client);
    drop(connection);

    let database_path = database.to_str().expect("UTF-8 runtime database path");
    let runtime_authority_id =
        runne_application::ports::RuntimeAuthorityId(hex::encode(authority_id));
    let writer = runne_store::schema::reopen_managed_connection_validated(
        database,
        runne_store::schema::ConnectionMode::ValidatedReopen,
        |connection| validate_native_runtime_identity(connection, authority_id, lineage_id),
    )
    .expect("reopen validated managed writer after both supervisors stopped");
    let reader = runne_store::schema::reopen_managed_connection_validated(
        database,
        runne_store::schema::ConnectionMode::Reader,
        |connection| validate_native_runtime_identity(connection, authority_id, lineage_id),
    )
    .expect("reopen validated managed reader for saved identity");
    let store = runne_store::store::StoreTransaction::open_with_connections(
        database_path,
        writer,
        reader,
        runtime_authority_id.clone(),
        std::sync::Arc::new(FreshClaimAllowContent),
    )
    .expect("open existing store without a permission owner");

    (
        runtime_authority_id,
        store,
        node_id,
        node_epoch,
        terminal_version,
    )
}
