use super::*;

pub(super) async fn exercise_daemon_crash_recovery(
    context: &mut super::t1_taskrun_support::LocalTaskRunContext<'_>,
    expected_permission_mode: Option<runne_api::PermissionModeV1>,
) {
    let client = &context.client;
    let conversation_id = context.conversation_id;
    let workspace_id = context.workspace_id;
    let project_directory = context.project_directory;
    let database = context.database;
    let runtime_root = context.runtime_root;
    let executable = context.executable;
    let supervisor = &mut *context.supervisor;
    eprintln!("RUN: protected local-command daemon crash and restart recovery");
    let permission_before = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected permission mode before local crash");
    if let Some(expected) = expected_permission_mode {
        assert_eq!(permission_before.selected_mode, expected);
    }
    let marker = project_directory.join("crash-execution-count");
    let leader = project_directory.join("crash-leader-started");
    let detached = project_directory.join("crash-detached-started");
    for path in [&marker, &leader, &detached] {
        std::fs::write(path, "").expect("prepare restart fixture marker");
    }
    let script = format!(
        "printf 'run\\n' >> '{}'; setsid bash -c 'trap \"\" TERM; printf child > \"{}\"; while true; do sleep 0.1; done' & child=$!; printf leader > '{}'; wait \"$child\"",
        marker.display(),
        detached.display(),
        leader.display()
    );
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec!["bash".into(), "-c".into(), script],
        Vec::new(),
    )
    .expect("valid structured restart command");
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("t1-local-crash-{}", uuid::Uuid::now_v7()),
    )
    .expect("restart fixture submit identity");
    let submitted = client
        .submit_task_run(
            runne_runtime_client::SubmitTaskRunRequest::new(
                identity,
                conversation_id,
                workspace_id,
                "Run the explicitly approved restart recovery fixture",
            )
            .expect("restart command description")
            .with_local_command(command)
            .expect("typed local restart command"),
        )
        .await
        .expect("submit restart command");
    let task_run_id = submitted.task_run_id();
    if permission_before.selected_mode == runne_api::PermissionModeV1::FullAccess {
        let run_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if client
                .get_task_run(task_run_id)
                .await
                .expect("read full-access restart fixture")
                .state()
                == runne_runtime_client::TaskRunState::Running
            {
                break;
            }
            assert!(tokio::time::Instant::now() < run_deadline);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            client
                .list_pending_approvals()
                .await
                .expect("list full-access restart approvals")
                .into_iter()
                .all(|item| item.task_run_id() != task_run_id)
        );
    } else {
        let approval_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let approval = loop {
            if let Some(approval) = client
                .list_pending_approvals()
                .await
                .expect("list restart approval")
                .into_iter()
                .find(|item| item.task_run_id() == task_run_id)
            {
                break approval;
            }
            assert!(tokio::time::Instant::now() < approval_deadline);
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let approval_command = runne_runtime_client::ApprovalDecisionRequest::new(
            runne_runtime_client::CommandIdentity::new(
                runne_runtime_client::CanonicalId::now_v7(),
                format!("t1-local-crash-approve-{}", uuid::Uuid::now_v7()),
            )
            .unwrap(),
            approval.approval_id(),
            approval.request_version(),
            runne_runtime_client::ApprovalDecisionDto::Approve,
            *approval.action_digest(),
            approval.policy_revision(),
            1,
        )
        .unwrap();
        client
            .decide_approval(approval_command)
            .await
            .expect("approve exact restart command");
    }
    wait_for_file(&leader).await;
    wait_for_file(&detached).await;
    let run_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .get_task_run(task_run_id)
            .await
            .expect("read running restart fixture")
            .state()
            == runne_runtime_client::TaskRunState::Running
        {
            break;
        }
        assert!(tokio::time::Instant::now() < run_deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "run\n");
    let task_bytes = uuid::Uuid::parse_str(&task_run_id.to_string())
        .expect("TaskRun identifier")
        .into_bytes();
    let route_connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open pre-crash route read-only");
    let route: (i64, i64, i64) = route_connection
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes
             WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read committed pre-crash permission route");
    assert_eq!(route, (2, 3, 68));
    drop(route_connection);
    let pid = supervisor.test_owned_child_id() as libc::pid_t;
    let killed = unsafe { libc::kill(pid, libc::SIGKILL) };
    assert_eq!(killed, 0, "SIGKILL only the exact supervised daemon");
    assert_eq!(
        supervisor
            .test_wait_for_exit(Duration::from_secs(10))
            .expect("reap killed supervised daemon"),
        runne_platform_desktop::BundledRuntimeProcessStatus::Exited,
        "the exact SIGKILLed supervisor child exited"
    );
    supervisor.stop().expect("clear reaped supervisor handle");

    let socket = super::t1_support::fixture_session_bus(
        runtime_root.parent().expect("temporary runtime parent"),
        "local-command-restart-bus.sock",
    );
    let spec = runne_platform_desktop::ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        runtime_root,
    )
    .expect("restart launch spec")
    .with_openai_provider_activation()
    .with_validated_session_bus_address(&socket)
    .expect("restart fixture session bus");
    let mut restarted = runne_platform_desktop::ProtectedBundledRuntimeSupervisor::new(
        runne_platform_desktop::DevelopmentBundledRuntimeLauncher::new(),
        spec,
    );
    if let Err(error) = restarted.start() {
        let status: Option<(String, i64)> = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()
        .and_then(|connection| {
            connection
                .query_row(
                    "SELECT attempt.state,stream.current_version
                         FROM taskrun_local_command_attempts attempt
                         JOIN aggregate_streams stream ON stream.aggregate_type=1
                           AND stream.aggregate_id=attempt.taskrun_id
                         WHERE attempt.taskrun_id=?1",
                    [task_bytes.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .ok()
        });
        panic!("restart same protected runtime root: {error}; local_attempt={status:?}");
    }
    let restarted_client = restarted
        .take_runtime_profile()
        .expect("restarted runtime profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("connect restarted daemon");
    restarted
        .record_client_ready(&restarted_client)
        .expect("record restarted profile readiness");
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
        std::fs::read_to_string(&marker).unwrap(),
        "run\n",
        "recovery observes and stops the old cgroup without relaunching"
    );
    assert!(
        std::fs::read_to_string(&detached).is_ok(),
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
    let taskrun_domain_id = runne_domain::id::TaskRunId::from_bytes(task_bytes);
    let effects_before =
        runne_application::ports::EventStore::load_task_run_effects(&store, taskrun_domain_id)
            .expect("read recovered effects through the reopened store");
    let before_connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open post-shutdown native claim baseline reader");
    let before = native_unknown_fresh_claim_snapshot(
        &before_connection,
        task_bytes.as_slice(),
        effects_before,
    )
    .expect("snapshot recovered state before fresh claim");
    drop(before_connection);
    assert_eq!(before.local_attempts.len(), 1);
    assert_eq!(before.stop_receipts.len(), 1);
    assert_eq!(before.terminal_receipts.len(), 1);
    assert_eq!(before.assignment_occupations.len(), 1);
    assert_eq!(before.claim_receipts.len(), 1);
    assert_eq!(before.effects.stream_version, terminal_version);
    assert_eq!(
        before.effects.local_command.as_ref().map(|local| (
            local.outcome,
            local.stop,
            local.exit_code
        )),
        Some((
            runne_api::LocalCommandOutcomeV1::OutcomeUnknown,
            runne_api::LocalCommandStopV1::Confirmed,
            None
        )),
        "reopened effects retain unknown outcome and confirmed stop"
    );

    let command_uuid = uuid::Uuid::now_v7();
    // DaemonAutomaticTaskRuns::runtime_context uses this runtime principal and actor.
    let claim_context = runne_application::ports::ApplicationCommandContext {
        command_id: runne_domain::id::CommandId::from_bytes(*command_uuid.as_bytes()),
        idempotency_key: runne_domain::id::IdempotencyKey::new(format!(
            "native-unknown-fresh-claim-{command_uuid}"
        ))
        .expect("fresh native claim idempotency key"),
        principal_id: runne_application::ports::PrincipalId("runne-runtime".into()),
        actor: runne_domain::event::Actor::new("runne-runtime")
            .expect("built-in runtime actor identity"),
    };
    let claim_port = FreshClaimReadOnlyPort {
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
            node_epoch: u64::try_from(node_epoch).expect("current node epoch is positive"),
            capability_descriptor: "linux-executor-v1".into(),
            lease_duration_ms: 300_000,
        },
        &claim_port,
    );
    assert_eq!(
        claim_result,
        Err(runne_application::service::ClaimTaskRunServiceError::NotQueued),
        "a fresh canonical claim retry rejects the recovered terminal TaskRun"
    );
    assert_eq!(
        claim_port.lookups.get(),
        2,
        "the service performed both read-only receipt lookups"
    );
    let effects_after =
        runne_application::ports::EventStore::load_task_run_effects(&store, taskrun_domain_id)
            .expect("read recovered effects after fresh claim rejection");
    let after_connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open post-claim native state reader");
    let after = native_unknown_fresh_claim_snapshot(
        &after_connection,
        task_bytes.as_slice(),
        effects_after,
    )
    .expect("snapshot recovered state after fresh claim");
    assert_eq!(after, before, "fresh claim rejection appended no state");
    eprintln!("PASS: protected local-command daemon crash and restart recovery");
}

#[derive(Debug, PartialEq)]
struct NativeUnknownFreshClaimSnapshot {
    stream: Vec<Vec<rusqlite::types::Value>>,
    event_ids: Vec<Vec<rusqlite::types::Value>>,
    effects: runne_api::TaskRunEffectsV1,
    local_attempts: Vec<Vec<rusqlite::types::Value>>,
    stop_receipts: Vec<Vec<rusqlite::types::Value>>,
    terminal_receipts: Vec<Vec<rusqlite::types::Value>>,
    assignments: Vec<Vec<rusqlite::types::Value>>,
    assignment_occupations: Vec<Vec<rusqlite::types::Value>>,
    claim_receipts: Vec<Vec<rusqlite::types::Value>>,
    lease_renewals: Vec<Vec<rusqlite::types::Value>>,
    execution_nodes: Vec<Vec<rusqlite::types::Value>>,
    append_bytes: Vec<Vec<rusqlite::types::Value>>,
}

fn native_unknown_fresh_claim_snapshot(
    connection: &rusqlite::Connection,
    taskrun_id: &[u8],
    effects: runne_api::TaskRunEffectsV1,
) -> rusqlite::Result<NativeUnknownFreshClaimSnapshot> {
    Ok(NativeUnknownFreshClaimSnapshot {
        stream: native_claim_rows(
            connection,
            "SELECT * FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_id],
        )?,
        event_ids: native_claim_rows(
            connection,
            "SELECT event_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
            [taskrun_id],
        )?,
        effects,
        local_attempts: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        stop_receipts: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        terminal_receipts: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        assignments: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_assignments WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        assignment_occupations: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        claim_receipts: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_claim_receipts WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        lease_renewals: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_assignment_lease_renewals WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        execution_nodes: native_claim_rows(
            connection,
            "SELECT * FROM execution_nodes ORDER BY node_id",
            rusqlite::params![],
        )?,
        append_bytes: native_claim_rows(
            connection,
            "SELECT command_id,idempotency_key,actor,payload,integrity_digest,correlation_id
             FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
            [taskrun_id],
        )?,
    })
}

fn native_claim_rows<P: rusqlite::Params>(
    connection: &rusqlite::Connection,
    sql: &str,
    parameters: P,
) -> rusqlite::Result<Vec<Vec<rusqlite::types::Value>>> {
    let mut statement = connection.prepare(sql)?;
    let column_count = statement.column_count();
    statement
        .query_map(parameters, |row| {
            (0..column_count)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?
        .collect()
}

fn validate_native_runtime_identity(
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

struct FreshClaimAllowContent;

impl runne_application::prohibited_content::ProhibitedContentPort for FreshClaimAllowContent {
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

struct FreshClaimReadOnlyPort<'a> {
    store: &'a runne_store::store::StoreTransaction,
    lookups: std::cell::Cell<usize>,
}

impl runne_application::ports::TaskRunClaimPort for FreshClaimReadOnlyPort<'_> {
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
        panic!("terminal fresh-claim preflight must not reach the mutating port")
    }
}

async fn wait_for_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "fixture marker did not appear"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
