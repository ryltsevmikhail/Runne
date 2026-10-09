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

#[path = "t1_local_lost_ack_parts/assertions.rs"]
mod assertions;
#[path = "t1_local_lost_ack_parts/native_state.rs"]
mod native_state;

use assertions::{assert_replay_is_inert, reject_fresh_claim_under_new_id};

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
                    format!("t1-local-lost-ack-approve-{}", uuid::Uuid::now_v7()),
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
    assert_eq!(
        released, "released",
        "occupation is released before the kill"
    );
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
    context
        .supervisor
        .stop()
        .expect("clear reaped supervisor handle");
    // Release the gate before any restart: the restarted daemon inherits the
    // same gate environment, and a present release file keeps any later
    // terminal commit from parking until the 60 s gate deadline.
    let gate_release = std::env::var_os("RUNNE_TEST_COMMIT_GATE_RELEASE")
        .expect("lost-ACK terminal commit-gate release path");
    std::fs::write(&gate_release, b"release").expect("release the lost-ACK terminal commit gate");

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
    let local = effects
        .local_command()
        .expect("lost-ACK local effect receipt");
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
    reject_fresh_claim_under_new_id(
        context,
        task_bytes,
        authority_id,
        lineage_id,
        terminal_version,
    )
    .await;
    eprintln!("PASS: protected local-command lost ACK replays exactly and never redispatches");
    true
}
