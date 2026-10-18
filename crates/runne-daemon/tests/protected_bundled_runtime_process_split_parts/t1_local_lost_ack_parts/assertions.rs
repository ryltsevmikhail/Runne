use std::time::Duration;

use super::super::super::t1_taskrun_support::LocalTaskRunContext;
use super::native_state::{
    AllowContent, ReadOnlyClaimPort, current_execution_node, full_database_snapshot,
    validate_runtime_identity,
};

/// A same-identity resubmission keeps one TaskRun identity and appends
/// neither a stream version, a second child effect, nor a second attempt.
pub(super) async fn assert_replay_is_inert(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    request: &runne_runtime_client::SubmitTaskRunRequest,
    task_id: runne_runtime_client::CanonicalId,
    terminal: &runne_runtime_client::TaskRunSnapshot,
    database: &std::path::Path,
    marker: &std::path::Path,
) {
    let replay = client
        .submit_task_run(request.clone())
        .await
        .expect("replay the identical lost-ACK submission");
    assert_eq!(replay.task_run_id(), task_id, "replay keeps one identity");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let reread = client
        .get_task_run(task_id)
        .await
        .expect("read lost-ACK TaskRun after replay");
    assert_eq!(
        reread.state(),
        runne_runtime_client::TaskRunState::Succeeded
    );
    assert_eq!(reread.stream_version(), terminal.stream_version());
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        "lost-ack\n",
        "replay produces no second filesystem effect"
    );
    let task_bytes = uuid::Uuid::parse_str(&task_id.to_string())
        .expect("TaskRun identifier")
        .into_bytes();
    let attempts: i64 =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open replay attempt counter")
            .query_row(
                "SELECT COUNT(*) FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
                [task_bytes.as_slice()],
                |row| row.get(0),
            )
            .expect("count lost-ACK attempts");
    assert_eq!(attempts, 1, "no blind redispatch of the settled TaskRun");
}

/// A retry under a brand-new command identity on the reopened store is
/// rejected with `NotQueued`, never reaches the mutating claim port, and
/// leaves the whole durable database byte-identical.
pub(super) async fn reject_fresh_claim_under_new_id(
    context: &mut LocalTaskRunContext<'_>,
    task_bytes: [u8; 16],
    authority_id: [u8; 16],
    lineage_id: runne_domain::id::EventLogLineageId,
    terminal_version: u64,
) {
    let database_path = context
        .database
        .to_str()
        .expect("UTF-8 runtime database path");
    let runtime_authority_id =
        runne_application::ports::RuntimeAuthorityId(hex::encode(authority_id));
    let writer = runne_store::schema::reopen_managed_connection_validated(
        context.database,
        runne_store::schema::ConnectionMode::ValidatedReopen,
        |connection| validate_runtime_identity(connection, authority_id, lineage_id),
    )
    .expect("reopen validated writer after the lost-ACK restarts");
    let reader = runne_store::schema::reopen_managed_connection_validated(
        context.database,
        runne_store::schema::ConnectionMode::Reader,
        |connection| validate_runtime_identity(connection, authority_id, lineage_id),
    )
    .expect("reopen validated reader for the saved identity");
    let store = runne_store::store::StoreTransaction::open_with_connections(
        database_path,
        writer,
        reader,
        runtime_authority_id.clone(),
        std::sync::Arc::new(AllowContent),
    )
    .expect("reopen the lost-ACK store without a permission owner");
    let taskrun_domain_id = runne_domain::id::TaskRunId::from_bytes(task_bytes);
    let effects_before =
        runne_application::ports::EventStore::load_task_run_effects(&store, taskrun_domain_id)
            .expect("load lost-ACK effects before the new-ID claim");
    let before = full_database_snapshot(context.database);

    let command_uuid = uuid::Uuid::now_v7();
    // DaemonAutomaticTaskRuns::runtime_context uses this runtime principal and actor.
    let claim_context = runne_application::ports::ApplicationCommandContext {
        command_id: runne_domain::id::CommandId::from_bytes(*command_uuid.as_bytes()),
        idempotency_key: runne_domain::id::IdempotencyKey::new(format!(
            "lost-ack-fresh-claim-{command_uuid}"
        ))
        .expect("fresh lost-ACK claim idempotency key"),
        principal_id: runne_application::ports::PrincipalId("runne-runtime".into()),
        actor: runne_domain::event::Actor::new("runne-runtime")
            .expect("built-in runtime actor identity"),
    };
    let (node_id, node_epoch) = current_execution_node(context.database);
    let claim_port = ReadOnlyClaimPort {
        store: &store,
        lookups: std::cell::Cell::new(0),
    };
    let service = runne_application::service::TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        runtime_authority_id,
    );
    let claim_result = service.claim_task_run(
        &claim_context,
        runne_application::service::ClaimTaskRunInput {
            taskrun_id: taskrun_domain_id,
            expected_version: terminal_version,
            node_id: runne_application::ports::ExecutionNodeId(
                uuid::Uuid::from_bytes(node_id).to_string(),
            ),
            node_epoch,
            capability_descriptor: "linux-executor-v1".into(),
            lease_duration_ms: 300_000,
        },
        &claim_port,
    );
    assert_eq!(
        claim_result,
        Err(runne_application::service::ClaimTaskRunServiceError::NotQueued),
        "a retry under a new command identity is not blindly redispatched"
    );
    assert_eq!(
        claim_port.lookups.get(),
        2,
        "the service performed both read-only receipt lookups"
    );
    let effects_after =
        runne_application::ports::EventStore::load_task_run_effects(&store, taskrun_domain_id)
            .expect("load lost-ACK effects after the rejected claim");
    assert_eq!(effects_after, effects_before);
    assert_eq!(
        full_database_snapshot(context.database),
        before,
        "the rejected new-ID claim appended no durable state"
    );
}
