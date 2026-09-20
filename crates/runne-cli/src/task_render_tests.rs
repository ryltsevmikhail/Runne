//! Unit matrix for the read-only `task` command rendering and parsing: the
//! full 15-state lifecycle is exercised through the CLI-side view DTO without
//! a runtime server, because the opaque `TaskRunSnapshot` has no public
//! constructor and terminal states are not reachable through the client-facing
//! submit path in fixtures.

use super::*;

const SAMPLE_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
const SAMPLE_ATTEMPT: &str = "018f2e3a-7000-7000-8000-000000000002";

/// `(state, wire name)` for every `TaskRunState` variant.
const ALL_STATES: &[(TaskRunState, &str)] = &[
    (TaskRunState::Created, "created"),
    (TaskRunState::Queued, "queued"),
    (TaskRunState::Admitted, "admitted"),
    (TaskRunState::Running, "running"),
    (TaskRunState::Waiting, "waiting"),
    (TaskRunState::Retrying, "retrying"),
    (TaskRunState::Checkpointing, "checkpointing"),
    (TaskRunState::Cancelling, "cancelling"),
    (TaskRunState::Reconciling, "reconciling"),
    (TaskRunState::Succeeded, "succeeded"),
    (TaskRunState::Failed, "failed"),
    (TaskRunState::Cancelled, "cancelled"),
    (TaskRunState::BudgetExhausted, "budget_exhausted"),
    (TaskRunState::PolicyDenied, "policy_denied"),
    (TaskRunState::Unrecoverable, "unrecoverable"),
];

fn view(
    state: TaskRunState,
    attempt: Option<&str>,
    terminal: Option<TaskTerminalResultView>,
) -> TaskRunView {
    TaskRunView {
        task_run_id: SAMPLE_ID.to_owned(),
        state: task_state_name(state),
        stream_version: 3,
        active_attempt_id: attempt.map(str::to_owned),
        terminal_result: terminal,
    }
}

fn failure_result(reason: &str) -> TaskTerminalResultView {
    TaskTerminalResultView {
        outcome: "failure",
        reason: Some(reason.to_owned()),
    }
}

#[test]
fn every_state_renders_its_snake_case_wire_name() {
    for (state, name) in ALL_STATES {
        assert_eq!(task_state_name(*state), *name, "{name}");
        let row = format_task_list_text(&[view(*state, None, None)]);
        assert!(row.contains(&format!("\t{name}\t")), "{row}");
        let block = format_task_get_text(&view(*state, None, None));
        assert!(block.contains(&format!("state: {name}")), "{block}");
        assert_eq!(
            task_get_json_data(&view(*state, None, None))["state"],
            *name
        );
    }
}

#[test]
fn terminal_results_render_success_failure_and_dash() {
    let success = view(
        TaskRunState::Succeeded,
        None,
        Some(TaskTerminalResultView {
            outcome: "success",
            reason: None,
        }),
    );
    let success_json = task_get_json_data(&success);
    assert!(
        format_task_get_text(&success).contains("terminal result: success"),
        "{}",
        format_task_get_text(&success)
    );
    assert_eq!(success_json["terminalResult"]["type"], "success");

    let failed = view(
        TaskRunState::Failed,
        None,
        Some(failure_result("provider blew up")),
    );
    let failed_text = format_task_get_text(&failed);
    assert!(
        failed_text.contains("terminal result: failure: provider blew up"),
        "{failed_text}"
    );
    let failed_json = task_get_json_data(&failed);
    assert_eq!(failed_json["terminalResult"]["type"], "failure");
    assert_eq!(failed_json["terminalResult"]["reason"], "provider blew up");

    let pending = view(TaskRunState::Queued, None, None);
    assert!(
        format_task_get_text(&pending).contains("terminal result: -"),
        "{}",
        format_task_get_text(&pending)
    );
    assert!(task_get_json_data(&pending)["terminalResult"].is_null());
}

#[test]
fn active_attempts_render_as_dash_or_identifier() {
    let pending = format_task_get_text(&view(TaskRunState::Created, None, None));
    assert!(pending.contains("active attempt: -"), "{pending}");
    assert!(
        task_get_json_data(&view(TaskRunState::Created, None, None))["activeAttemptId"].is_null()
    );

    let running = format_task_get_text(&view(TaskRunState::Running, Some(SAMPLE_ATTEMPT), None));
    assert!(
        running.contains(&format!("active attempt: {SAMPLE_ATTEMPT}")),
        "{running}"
    );
    assert_eq!(
        task_get_json_data(&view(TaskRunState::Running, Some(SAMPLE_ATTEMPT), None))["activeAttemptId"],
        SAMPLE_ATTEMPT
    );
}

#[test]
fn empty_list_renders_placeholder_and_typed_empty_array() {
    assert_eq!(format_task_list_text(&[]), "no task runs");
    let data = task_list_json_data(&[]);
    assert_eq!(data["taskRuns"].as_array().expect("taskRuns").len(), 0);
}

#[test]
fn list_rows_have_five_tab_separated_columns() {
    let views = vec![
        view(TaskRunState::Created, None, None),
        view(
            TaskRunState::Succeeded,
            None,
            Some(TaskTerminalResultView {
                outcome: "success",
                reason: None,
            }),
        ),
    ];
    let text = format_task_list_text(&views);
    let rows: Vec<&str> = text.lines().collect();
    assert_eq!(rows.len(), 2, "{text}");
    for row in rows {
        assert_eq!(row.split('\t').count(), 5, "{row}");
    }
    let data = task_list_json_data(&views);
    let runs = data["taskRuns"].as_array().expect("taskRuns");
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0]["taskRunId"], SAMPLE_ID);
    assert_eq!(runs[1]["state"], "succeeded");
}

#[test]
fn json_envelope_carries_typed_data_without_output_key() {
    let views = vec![view(TaskRunState::Running, Some(SAMPLE_ATTEMPT), None)];
    let output = CommandOutput::typed(format_task_list_text(&views), task_list_json_data(&views));
    let outcome = process_outcome(Ok(output), OutputFormat::Json);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stderr.is_empty());
    let envelope: serde_json::Value =
        serde_json::from_str(&outcome.stdout).expect("one-parse JSON envelope");
    assert_eq!(envelope["schemaVersion"], 1);
    assert_eq!(envelope["ok"], true);
    assert!(
        envelope["data"].get("output").is_none(),
        "stringly data.output payload is forbidden"
    );
    assert_eq!(
        envelope["data"]["taskRuns"][0]["activeAttemptId"],
        SAMPLE_ATTEMPT
    );
}

#[test]
fn task_get_parse_accepts_one_uuidv7_flag() {
    let arguments: VecDeque<OsString> = ["--task-run-id", SAMPLE_ID]
        .iter()
        .map(OsString::from)
        .collect();
    match parse_task_get(arguments) {
        Ok(TaskCommand::Get { task_run_id }) => {
            assert_eq!(task_run_id.to_string(), SAMPLE_ID);
        }
        other => panic!("expected Get, got {other:?}"),
    }
}

#[test]
fn task_get_parse_rejects_malformed_non_v7_and_extra_input() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["--task-run-id", "not-a-uuid"],
        // Valid RFC 4122 UUID, but version 4: only UUIDv7 is accepted.
        vec!["--task-run-id", "5d3a7c8e-1a2b-4c3d-8e9f-0a1b2c3d4e5f"],
        vec!["--task-run-id"],
        vec!["--task-run-id", SAMPLE_ID, "extra"],
        vec!["--conversation-id", SAMPLE_ID],
    ];
    for arguments in cases {
        let parsed: VecDeque<OsString> = arguments.iter().map(OsString::from).collect();
        assert!(
            matches!(parse_task_get(parsed), Err(CliError::Usage)),
            "{arguments:?} must be a usage error"
        );
    }
}

#[test]
fn task_get_parse_resolves_subcommand_help() {
    let arguments: VecDeque<OsString> = std::iter::once(OsString::from("--help")).collect();
    match parse_task_get(arguments) {
        Err(CliError::Help(text)) => assert_eq!(text, TASK_GET_HELP),
        other => panic!("expected help, got {other:?}"),
    }
}

#[test]
fn help_paths_resolve_task_texts() {
    assert_eq!(help_for(&["task"]), TASK_HELP);
    assert_eq!(help_for(&["task", "list"]), TASK_LIST_HELP);
    assert_eq!(help_for(&["task", "get"]), TASK_GET_HELP);
}
