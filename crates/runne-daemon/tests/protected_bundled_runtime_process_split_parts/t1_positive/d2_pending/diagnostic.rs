#[path = "diagnostic/stage.rs"]
mod stage;
#[path = "diagnostic/watch.rs"]
mod watch;
pub(super) use watch::{count_watch_mask, open_create_watch, open_watch, read_watch};
pub(super) fn diagnostic(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    runtime_root: &std::path::Path,
) -> String {
    let remote_stage = store_remote_stage();
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only D2 diagnostics");
    let version: i64 = connection
        .query_row(
            "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("read TaskRun stream head");
    let mut event_statement = connection
        .prepare("SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence")
        .expect("prepare TaskRun event diagnostic query");
    let payloads = event_statement
        .query_map([task_bytes.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .expect("query TaskRun event diagnostic payloads")
        .collect::<Result<Vec<_>, _>>()
        .expect("read TaskRun event diagnostic payloads");
    let events = payloads
        .iter()
        .map(|payload| {
            use runne_store::codec::{StoreCodec, TaskRunEventCodec};
            TaskRunEventCodec
                .decode(payload)
                .expect("decode canonical TaskRun event for enum-only diagnostic")
        })
        .collect::<Vec<_>>();
    let tail_event_kind = events
        .last()
        .map(|event| format!("{:?}", event.kind()))
        .unwrap_or_else(|| "empty".to_owned());
    let taskrun_state = match events.last() {
        Some(runne_domain::task_run::TaskRunEvent::TaskRunCancelled)
        | Some(runne_domain::task_run::TaskRunEvent::CancellationCompleted) => "Cancelled",
        Some(runne_domain::task_run::TaskRunEvent::TaskRunFailed { .. }) => "Failed",
        Some(runne_domain::task_run::TaskRunEvent::TaskRunCompleted { .. }) => "Completed",
        Some(runne_domain::task_run::TaskRunEvent::CancellationRequested) => "Cancelling",
        _ => "Nonterminal-or-cycle-update",
    };
    let event_metadata = events
        .iter()
        .map(|event| match event {
            runne_domain::task_run::TaskRunEvent::TaskRunSubmitted { .. } => "Submitted",
            runne_domain::task_run::TaskRunEvent::AttemptStarted { .. } => "AttemptStarted",
            runne_domain::task_run::TaskRunEvent::LoopCycleStarted { .. } => "LoopCycleStarted",
            runne_domain::task_run::TaskRunEvent::ContextCommitted { .. } => "ContextCommitted",
            runne_domain::task_run::TaskRunEvent::PlanCommitted { .. } => "PlanCommitted",
            runne_domain::task_run::TaskRunEvent::StepOutcomeRecorded { .. } => {
                "StepOutcomeRecorded"
            }
            runne_domain::task_run::TaskRunEvent::CancellationRequested => "CancellationRequested",
            runne_domain::task_run::TaskRunEvent::CancellationCompleted => "CancellationCompleted",
            runne_domain::task_run::TaskRunEvent::TaskRunCancelled => "TaskRunCancelled",
            runne_domain::task_run::TaskRunEvent::LoopCycleCompleted { .. } => "LoopCycleCompleted",
            runne_domain::task_run::TaskRunEvent::TaskRunCompleted { .. } => "TaskRunCompleted",
            runne_domain::task_run::TaskRunEvent::TaskRunFailed { .. } => "TaskRunFailed",
            _ => "other",
        })
        .collect::<Vec<_>>()
        .join(",");
    let invocations: i64 = connection
        .query_row(
            "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("read tool invocation count");
    let rounds: i64 = connection
        .query_row(
            "SELECT count(*) FROM taskrun_provider_round_bindings WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("read provider round count");
    use rusqlite::OptionalExtension as _;
    let effects: Option<i64> = connection
        .query_row(
            "SELECT effects_used FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .expect("read optional tool effect count");
    let approvals: i64 = connection
        .query_row(
            "SELECT count(*) FROM approvals WHERE task_run_id=?1",
            [task.to_string()],
            |row| row.get(0),
        )
        .expect("read pending approval count");
    let invocation_states = invocation_states(&connection, task_bytes.as_slice());
    let (dispatches, journal_events, outboxes): (i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM provider_execution_admissions WHERE taskrun_id=?1), (SELECT count(*) FROM provider_stream_journal j JOIN provider_execution_admissions a ON a.dispatch_attempt_id=j.dispatch_attempt_id WHERE a.taskrun_id=?1), (SELECT count(*) FROM provider_terminal_outbox o JOIN provider_execution_admissions a ON a.dispatch_attempt_id=o.dispatch_attempt_id WHERE a.taskrun_id=?1)",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read bounded D2 provider journal counts");
    let (dispatch_states, journal_kinds, outbox_states): (Option<String>, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT (SELECT group_concat(d.state) FROM provider_execution_admissions a JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id WHERE a.taskrun_id=?1), (SELECT group_concat(j.event_kind) FROM provider_execution_admissions a JOIN provider_stream_journal j ON j.dispatch_attempt_id=a.dispatch_attempt_id WHERE a.taskrun_id=?1), (SELECT group_concat(o.state) FROM provider_execution_admissions a JOIN provider_terminal_outbox o ON o.dispatch_attempt_id=a.dispatch_attempt_id WHERE a.taskrun_id=?1)",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read bounded D2 dispatch state and journal kinds");
    let (terminal_artifacts, settlements, terminal_facts): (i64, i64, Option<String>) = connection
        .query_row(
            "SELECT count(DISTINCT t.dispatch_attempt_id),count(DISTINCT s.dispatch_attempt_id),
                    group_concat(CASE WHEN s.dispatch_attempt_id IS NOT NULL
                                      THEN s.terminal_status || ':' || s.publication_disposition || ':' || s.settlement_state END)
             FROM provider_remote_request_intents q
             LEFT JOIN provider_remote_terminal_artifacts t USING(dispatch_attempt_id)
             LEFT JOIN provider_remote_terminal_settlements s USING(dispatch_attempt_id)
             WHERE q.taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read bounded remote terminal enum diagnostics");
    let requests = fixture_count(runtime_root, "fixture-provider-request-count");
    let connections = fixture_count(runtime_root, "fixture-provider-connection-count");
    let d2_stage = stage::read(runtime_root);
    format!(
        "stage={d2_stage} remote_stage={remote_stage} task_version={version} task_state={taskrun_state} tail_event={tail_event_kind} event_kinds={event_metadata} provider_rounds={rounds} invocations={invocations} invocation_states={invocation_states} approvals={approvals} effects_used={effects:?} provider_requests={requests} provider_connections={connections} dispatches={dispatches} dispatch_states={dispatch_states:?} journal_events={journal_events} journal_kinds={journal_kinds:?} outboxes={outboxes} outbox_states={outbox_states:?} terminal_artifacts={terminal_artifacts} settlements={settlements} terminal_facts={terminal_facts:?}"
    )
}

pub(super) fn clear_store_remote_stage() {
    if let Some(directory) = std::env::var_os("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR") {
        let _ = std::fs::remove_file(
            std::path::Path::new(&directory).join(".runne-test-store-diagnostic-stage"),
        );
    }
}

fn store_remote_stage() -> &'static str {
    const ALLOWED: &[&str] = &[
        "remote.dispatch_lookup",
        "remote.d2_round_chain",
        "remote.dispatch_ambiguous",
        "remote.attempt_read",
        "remote.attempt_missing",
        "remote.attempt_binding",
        "remote.response_binding",
        "remote.submit_origin",
        "remote.expected_identity",
        "remote.fact_authentication",
        "remote.local_disposition",
        "remote.accounting_projection",
        "remote.grant_projection",
        "remote.credential_projection",
        "effects.stream_validation",
        "effects.taskrun_replay",
        "effects.submit_origin",
        "effects.local_row",
        "effects.local_binding",
        "effects.latest_attempt",
        "effects.local_terminal_proof",
        "effects.local_terminal_unproven",
        "effects.local_projection",
        "effects.local_row_optional",
        "effects.unexpected_local_row",
        "effects.remote_snapshot",
        "source.selected_profile",
        "source.claim_source",
        "source.claim_actor",
        "source.begin_source",
        "source.writer_lease",
        "source.applicability",
        "source.existing_pin",
    ];
    let Some(directory) = std::env::var_os("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR") else {
        return "unavailable";
    };
    let Ok(value) = std::fs::read_to_string(
        std::path::Path::new(&directory).join(".runne-test-store-diagnostic-stage"),
    ) else {
        return "unavailable";
    };
    let value = value.trim();
    ALLOWED
        .iter()
        .copied()
        .find(|stage| *stage == value)
        .unwrap_or("unavailable")
}

fn invocation_states(connection: &rusqlite::Connection, task: &[u8]) -> String {
    use rusqlite::OptionalExtension as _;
    let mut statement = connection
        .prepare("SELECT state,claim_fence IS NOT NULL AND claim_node_id IS NOT NULL AND claim_node_epoch IS NOT NULL,local_stop_state,release_started,approval_id FROM taskrun_tool_invocations WHERE taskrun_id=?1 ORDER BY round_index")
        .expect("prepare read-only invocation state query");
    let rows = statement
        .query_map([task], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .expect("query invocation states")
        .collect::<Result<Vec<_>, _>>()
        .expect("read invocation states");
    rows.into_iter()
        .map(|(state, assignment, local_stop, release, approval_id)| {
            let approval_text = uuid::Uuid::from_slice(&approval_id)
                .expect("approval UUID")
                .to_string();
            let decision = connection
                .query_row(
                    "SELECT state,decision FROM approvals WHERE approval_id=?1",
                    [approval_text],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
                )
                .optional()
                .expect("read persisted approval decision");
            format!(
                "state={state},claim_assignment={assignment},local_stop={local_stop},release_started={release},approval={decision:?}"
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

pub(super) fn fixture_count(root: &std::path::Path, name: &str) -> u64 {
    std::fs::read_to_string(root.join(name))
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}
