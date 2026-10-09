//! Plan 17 lines 135-136: «lost result ACK и повтор под новым ID: нет blind
//! redispatch и fabricated NotStarted».
//!
//! The worker commits the durable terminal settlement and then the daemon is
//! SIGKILLed before any client read consumes the terminal result (the lost
//! ACK). A same-root restart must return the exact stored outcome, a
//! same-identity submit must stay an inert replay, and a fresh claim under a
//! new command identity must be rejected with `NotQueued` without appending
//! any durable state.

use super::super::t1_taskrun_support::LocalTaskRunContext;
use std::time::Duration;

pub(super) async fn exercise(context: &mut LocalTaskRunContext<'_>) -> bool {
    eprintln!("RUN: protected local-command lost result ACK and new-ID retry");
    let marker = context.project_directory.join("lost-ack-marker");
    std::fs::write(&marker, "").expect("prepare lost-ACK effect marker");
    let script = format!("printf 'lost-ack\\n' >> '{}'; exit 0", marker.display());
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec!["bash".into(), "-c".into(), script],
        Vec::new(),
    )
    .expect("valid lost-ACK local command");
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("t1-local-lost-ack-{}", uuid::Uuid::now_v7()),
    )
    .expect("lost-ACK submit identity");
    let request = runne_runtime_client::SubmitTaskRunRequest::new(
        identity,
        context.conversation_id,
        context.workspace_id,
        "Run the explicitly approved lost-ACK fixture",
    )
    .expect("lost-ACK submit description")
    .with_local_command(command)
    .expect("typed lost-ACK local command");
    let task_id = context
        .client
        .submit_task_run(request.clone())
        .await
        .expect("submit lost-ACK command")
        .task_run_id();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let approval = loop {
        if let Some(row) = context
            .client
            .list_pending_approvals()
            .await
            .expect("list lost-ACK approval")
            .into_iter()
            .find(|row| row.task_run_id() == task_id)
        {
            break row;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "lost-ACK approval timeout; local_preapproval_stage={}",
            super::super::t1_startup_diagnostic::local_preapproval_diagnostic(context.runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    context
        .client
        .decide_approval(
            runne_runtime_client::ApprovalDecisionRequest::new(
                runne_runtime_client::CommandIdentity::new(
                    runne_runtime_client::CanonicalId::now_v7(),
                    format!(
                        "t1-local-lost-ack-approve-{}",
                        uuid::Uuid::now_v7()
                    ),
                )
                .unwrap(),
                approval.approval_id(),
                approval.request_version(),
                runne_runtime_client::ApprovalDecisionDto::Approve,
                *approval.action_digest(),
                approval.policy_revision(),
                1,
            )
            .unwrap(),
        )
        .await
        .expect("approve the exact lost-ACK command");
    // The worker now records the exit, completes the TaskRun and settles the
    // durable terminal receipt. The permission path never parks at the
    // after-terminal worker barrier, so the deterministic kill point is the
    // terminal commit gate instead: the daemon wrote the marker right after
    // the TaskRunCompleted tx.commit() and before any client ACK. This test
    // deliberately performs no get_task_run and no catch_up before the
    // SIGKILL below: the terminal read (the client's result ACK) is never
    // consumed — that lost ACK is the fault under test.
    let gate_marker = std::env::var_os("RUNNE_TEST_COMMIT_GATE_FILE")
        .expect("lost-ACK terminal commit-gate marker path");
    let gate_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !std::path::Path::new(&gate_marker).is_file() {
        assert!(
            tokio::time::Instant::now() < gate_deadline,
            "lost-ACK terminal commit-gate marker timeout at {}",
            gate_marker.to_string_lossy()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let task_bytes = uuid::Uuid::parse_str(&task_id.to_string())
        .expect("TaskRun identifier")
        .into_bytes();
    let connection = rusqlite::Connection::open_with_flags(
        context.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open pre-kill durable terminal reader");
    let (attempt_state, exit_code): (String, Option<i32>) = connection
        .query_row(
            "SELECT state,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("pre-kill local attempt row");
    assert_eq!(attempt_state, "completed");
    assert_eq!(exit_code, Some(0));
    let (receipt_count, released): (i64, String) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1),
                    occupation.state
             FROM taskrun_assignment_occupations occupation
             WHERE occupation.taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("pre-kill terminal receipt and occupation");
    assert_eq!(receipt_count, 1, "exactly one durable terminal receipt");
    assert_eq!(released, "released", "occupation is released before the kill");
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
        .expect("pre-kill terminal version");
    assert_eq!(terminal_version, current_version);
    assert_eq!(
        std::fs::read_to_string(&marker).expect("read lost-ACK marker"),
        "lost-ack\n",
        "the child effect happened exactly once before the kill"
    );
    let terminal_version = u64::try_from(terminal_version).expect("positive terminal version");
    let authority_id = runne_store::schema::read_authority_id(&connection)
        .expect("read runtime authority")
        .expect("runtime authority is present");
    let lineage_id = runne_store::schema::read_event_log_lineage_id(&connection)
        .expect("read event-log lineage")
        .expect("event-log lineage is present");
    let mut node_statement = connection
        .prepare("SELECT node_id,launch_generation FROM execution_nodes ORDER BY node_id")
        .expect("prepare execution-node read");
    let current_nodes = node_statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })
        .expect("read execution nodes")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect execution nodes");
    drop(node_statement);
    assert_eq!(current_nodes.len(), 1, "one current execution node");
    let (_node_id_bytes, node_epoch) = current_nodes.into_iter().next().unwrap();
    assert!(node_epoch > 0, "current execution-node epoch is positive");
    drop(connection);

    let daemon = context.supervisor.test_owned_child_id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(daemon, libc::SIGKILL) }, 0);
    context
        .supervisor
        .test_wait_for_exit(Duration::from_secs(10))
        .expect("reap the SIGKILLed daemon holding the unread terminal");
    context.supervisor.stop().expect("clear reaped supervisor handle");
    // Release the gate before any restart: the restarted daemon inherits the
    // same gate environment, and a present release file keeps any later
    // terminal commit from parking until the 60 s gate deadline.
    let gate_release = std::env::var_os("RUNNE_TEST_COMMIT_GATE_RELEASE")
        .expect("lost-ACK terminal commit-gate release path");
    std::fs::write(&gate_release, b"release")
        .expect("release the lost-ACK terminal commit gate");

    let (mut first, first_client) = super::super::t1_positive::restart_same_root(
        context.executable.path(),
        context.session_bus_socket,
        context.runtime_root,
    )
    .await;
    // First terminal read after the restart returns the exact stored outcome;
    // it must never fabricate a fresh NotStarted for the lost ACK.
    let terminal = first_client
        .get_task_run(task_id)
        .await
        .expect("first post-restart terminal read");
    assert_eq!(
        terminal.state(),
        runne_runtime_client::TaskRunState::Succeeded
    );
    assert!(matches!(
        terminal.terminal_result(),
        Some(runne_runtime_client::TaskRunTerminalResult::Success)
    ));
    assert_eq!(terminal.stream_version(), terminal_version);
    let stable = first_client
        .get_task_run(task_id)
        .await
        .expect("stable post-restart reread");
    assert_eq!(stable.stream_version(), terminal.stream_version());
    let effects = first_client
        .get_task_run_effects(task_id)
        .await
        .expect("post-restart local effect projection");
    let local = effects.local_command().expect("lost-ACK local effect receipt");
    assert_eq!(
        local.outcome(),
        runne_runtime_client::LocalExecutionOutcome::Exited
    );
    assert_eq!(
        local.stop(),
        runne_runtime_client::LocalStopEvidence::Confirmed
    );
    assert_eq!(local.exit_code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "lost-ack\n",
        "restart replays the result without repeating the child effect"
    );
    assert_replay_is_inert(
        &first_client,
        &request,
        task_id,
        &terminal,
        context.database,
        &marker,
    )
    .await;
    first.stop().expect("stop the first same-root restart");
    drop(first_client);

    let (mut second, second_client) = super::super::t1_positive::restart_same_root(
        context.executable.path(),
        context.session_bus_socket,
        context.runtime_root,
    )
    .await;
    assert_replay_is_inert(
        &second_client,
        &request,
        task_id,
        &terminal,
        context.database,
        &marker,
    )
    .await;
    second.stop().expect("stop the second same-root restart");
    drop(second_client);
    reject_fresh_claim_under_new_id(context, task_bytes, authority_id, lineage_id, terminal_version)
        .await;
    eprintln!("PASS: protected local-command lost ACK replays exactly and never redispatches");
    true
}

/// A same-identity resubmission keeps one TaskRun identity and appends
/// neither a stream version, a second child effect, nor a second attempt.
async fn assert_replay_is_inert(
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
    let attempts: i64 = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
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
async fn reject_fresh_claim_under_new_id(
    context: &mut LocalTaskRunContext<'_>,
    task_bytes: [u8; 16],
    authority_id: [u8; 16],
    lineage_id: runne_domain::id::EventLogLineageId,
    terminal_version: u64,
) {
    let database_path = context.database.to_str().expect("UTF-8 runtime database path");
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

fn current_execution_node(database: &std::path::Path) -> ([u8; 16], u64) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open execution-node reader");
    let (node_id_bytes, node_epoch): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT node_id,launch_generation FROM execution_nodes ORDER BY node_id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read the current execution node");
    (
        node_id_bytes.try_into().expect("node UUID bytes"),
        u64::try_from(node_epoch).expect("current node epoch is positive"),
    )
}

/// Snapshot every user table as sorted rendered rows so two snapshots compare
/// equal only when the whole durable database is unchanged.
fn full_database_snapshot(database: &std::path::Path) -> Vec<(String, Vec<String>)> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open full-database snapshot reader");
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .expect("prepare table inventory")
        .query_map([], |row| row.get(0))
        .expect("read table inventory")
        .collect::<rusqlite::Result<_>>()
        .expect("collect table inventory");
    tables
        .into_iter()
        .map(|table| {
            let mut rows: Vec<String> = snapshot_rows(&connection, &format!("SELECT * FROM \"{table}\""))
                .into_iter()
                .map(|row| format!("{row:?}"))
                .collect();
            rows.sort();
            (table, rows)
        })
        .collect()
}

fn snapshot_rows(
    connection: &rusqlite::Connection,
    sql: &str,
) -> Vec<Vec<rusqlite::types::Value>> {
    let mut statement = connection.prepare(sql).expect("prepare snapshot query");
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .expect("run snapshot query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect snapshot rows")
}

fn validate_runtime_identity(
    connection: &rusqlite::Connection,
    authority_id: [u8; 16],
    lineage_id: runne_domain::id::EventLogLineageId,
) -> rusqlite::Result<()> {
    if runne_store::schema::read_authority_id(connection)? == Some(authority_id)
        && runne_store::schema::read_event_log_lineage_id(connection)? == Some(lineage_id)
    {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

struct AllowContent;

impl runne_application::prohibited_content::ProhibitedContentPort for AllowContent {
    fn inspect(
        &self,
        _boundary: runne_application::prohibited_content::CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<
        runne_application::prohibited_content::ContentDisposition,
        runne_application::prohibited_content::ContentGuardError,
    > {
        Ok(runne_application::prohibited_content::ContentDisposition::Allowed { policy_epoch: 0 })
    }
}

struct ReadOnlyClaimPort<'a> {
    store: &'a runne_store::store::StoreTransaction,
    lookups: std::cell::Cell<usize>,
}

impl runne_application::ports::TaskRunClaimPort for ReadOnlyClaimPort<'_> {
    fn lookup_task_run_claim(
        &self,
        lookup: runne_application::ports::TaskRunClaimLookup,
    ) -> Result<
        runne_application::ports::TaskRunClaimLookupResult,
        runne_application::ports::TaskRunClaimError,
    > {
        self.lookups.set(self.lookups.get() + 1);
        runne_application::ports::TaskRunClaimPort::lookup_task_run_claim(self.store, lookup)
    }

    fn claim_task_run(
        &self,
        _request: runne_application::ports::TaskRunClaimRequest,
    ) -> Result<
        runne_application::ports::TaskRunClaimResult,
        runne_application::ports::TaskRunClaimError,
    > {
        panic!("the rejected new-ID claim must never reach the mutating port")
    }
}
