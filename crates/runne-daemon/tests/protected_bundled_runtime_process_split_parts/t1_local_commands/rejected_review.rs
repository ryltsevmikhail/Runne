pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &std::path::Path,
    database: &std::path::Path,
) {
    eprintln!("RUN: oversized local review is durably rejected before approval or launch");
    let marker = project_directory.join("oversized-review-must-not-run");
    std::fs::write(&marker, "").expect("prepare no-effect marker");
    let script = format!("printf executed >> '{}'; exit 0", marker.display());
    let large_argument = "x".repeat(6_000);
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec!["bash".into(), "-c".into(), script, large_argument],
        Vec::new(),
    )
    .expect("command remains within the accepted single-argument bound");
    let request = runne_runtime_client::SubmitTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-oversized-review-{}", uuid::Uuid::now_v7()),
        )
        .unwrap(),
        conversation_id,
        workspace_id,
        "Review must stay bounded and reject this command before dispatch",
    )
    .unwrap()
    .with_local_command(command)
    .unwrap();
    let task_id = client
        .submit_task_run(request)
        .await
        .expect("submit domain-valid local command")
        .task_run_id();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let terminal = loop {
        let snapshot = client.get_task_run(task_id).await.unwrap();
        if snapshot.state() == runne_runtime_client::TaskRunState::Failed {
            break snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "deterministic rejection must not remain queued: {:?}",
            snapshot.state()
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    let scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::TaskRun,
        task_id,
    );
    let mut kinds = Vec::new();
    client
        .catch_up(scope, None, |delivery| {
            if let runne_runtime_client::CanonicalReplayPayload::TaskRun(payload) =
                delivery.event().payload()
            {
                kinds.push(payload.kind());
            }
            Ok::<_, ()>(())
        })
        .await
        .expect("read durable rejected TaskRun history");
    assert_eq!(
        kinds.last(),
        Some(&runne_runtime_client::TaskRunTimelineKind::Failed),
        "the final public timeline event proves the rejection is terminal"
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == runne_runtime_client::TaskRunTimelineKind::Failed)
            .count(),
        1,
        "one deterministic rejection produces one terminal event"
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let stable = client.get_task_run(task_id).await.unwrap();
    assert_eq!(stable.state(), terminal.state());
    assert_eq!(stable.stream_version(), terminal.stream_version());
    assert!(
        client
            .list_pending_approvals()
            .await
            .unwrap()
            .into_iter()
            .all(|approval| approval.task_run_id() != task_id),
        "oversized review is rejected without creating an approval"
    );
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "",
        "rejected command never launched"
    );
    let id = uuid::Uuid::parse_str(&task_id.to_string())
        .expect("TaskRun identifier is a UUID")
        .into_bytes();
    let connection = rusqlite::Connection::open(database).expect("open runtime database");
    let (state, no_execution_binding, released, no_dispatch, no_stop, no_terminal, release_receipts):
        (String, bool, bool, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT a.state,
                    a.attempt_id IS NULL AND a.managed_area_identity IS NULL
                      AND a.exit_code IS NULL AND a.approval_id IS NULL,
                    EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts n
                           JOIN taskrun_assignment_occupations o USING(taskrun_id,fence)
                           WHERE n.taskrun_id=a.taskrun_id AND o.state='released'
                             AND o.dispatch_intent='absent' AND o.release_event_id=n.failure_event_id),
                    (SELECT COUNT(*) FROM taskrun_dispatch_intents d WHERE d.taskrun_id=a.taskrun_id),
                    (SELECT COUNT(*) FROM taskrun_local_command_stop_receipts s WHERE s.taskrun_id=a.taskrun_id),
                    (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts t WHERE t.taskrun_id=a.taskrun_id),
                    (SELECT COUNT(*) FROM taskrun_no_effect_release_receipts n WHERE n.taskrun_id=a.taskrun_id)
             FROM taskrun_local_command_attempts a WHERE a.taskrun_id=?1",
            [id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        )
        .expect("durable no-effect audit state exists");
    assert_eq!(state, "no_effect_terminal");
    assert!(
        no_execution_binding,
        "no attempt, managed area, exit, or approval binding was created"
    );
    assert!(
        released,
        "the original occupation is released with absent dispatch intent"
    );
    assert_eq!((no_dispatch, no_stop, no_terminal), (0, 0, 0));
    assert_eq!(
        release_receipts, 1,
        "one durable no-effect receipt proves the rejection"
    );
    let effects = client
        .get_task_run_effects(task_id)
        .await
        .expect("read public effect projection for rejected command");
    assert_eq!(effects.stream_version(), stable.stream_version());
    assert_eq!(
        effects
            .local_command()
            .expect("local no-effect outcome")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert_eq!(
        effects.remote().outcome(),
        runne_runtime_client::RemoteEffectOutcome::NotApplicable
    );
    eprintln!("PASS: oversized local review settles terminally before effect");
}
