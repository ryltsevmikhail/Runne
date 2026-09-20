// Read-only `task` command: inspect runtime task runs via the canonical client.
// Help texts live in cli/task_help.rs so harness scopes can share them.

#[derive(Debug)]
enum TaskCommand {
    List,
    Get { task_run_id: CanonicalId },
}

async fn run_task(
    profile_path: Option<PathBuf>,
    mut arguments: VecDeque<OsString>,
) -> Result<CommandOutput, CliError> {
    let profile_path = profile_path
        .or_else(|| default_local_profile_path().ok())
        .ok_or(CliError::Profile)?;

    let operation = pop_string(&mut arguments)?;

    // Check for --help after subcommand
    if operation == "--help" || operation == "-h" {
        return Err(CliError::Help(TASK_HELP.to_owned()));
    }

    let command = match operation.as_str() {
        "list" => {
            // Check for --help before the strict no-extra-arguments check
            if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
                return Err(CliError::Help(TASK_LIST_HELP.to_owned()));
            }
            expect_end(&arguments)?;
            TaskCommand::List
        }
        "get" => parse_task_get(arguments)?,
        _ => return Err(CliError::Usage),
    };

    let profile = LocalRuntimeProfile::load(&profile_path).map_err(|error| match error {
        LocalProfileError::Unavailable => CliError::Profile,
        LocalProfileError::InsecurePermissions | LocalProfileError::InvalidProfile => {
            CliError::ProfileIncompatible
        }
        LocalProfileError::InvalidCredential => CliError::ProfileIncompatible,
    })?;
    let client = profile
        .connect(REQUEST_TIMEOUT)
        .await
        .map_err(|error| match error {
            runne_runtime_client::LocalRuntimeConnectError::Transport(_) => CliError::Runtime,
            runne_runtime_client::LocalRuntimeConnectError::Api(error) => CliError::Api(error),
        })?;

    match command {
        TaskCommand::List => {
            let snapshots = client.list_task_runs().await.map_err(CliError::Api)?;
            let views: Vec<TaskRunView> = snapshots
                .iter()
                .map(TaskRunView::from_snapshot)
                .collect();
            Ok(CommandOutput::typed(
                format_task_list_text(&views),
                task_list_json_data(&views),
            ))
        }
        TaskCommand::Get { task_run_id } => {
            let snapshot = client
                .get_task_run(task_run_id)
                .await
                .map_err(CliError::Api)?;
            let view = TaskRunView::from_snapshot(&snapshot);
            Ok(CommandOutput::typed(
                format_task_get_text(&view),
                task_get_json_data(&view),
            ))
        }
    }
}

fn parse_task_get(mut arguments: VecDeque<OsString>) -> Result<TaskCommand, CliError> {
    // Check for --help
    if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
        return Err(CliError::Help(TASK_GET_HELP.to_owned()));
    }

    expect_token(&mut arguments, "--task-run-id")?;
    let task_run_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_end(&arguments)?;
    Ok(TaskCommand::Get { task_run_id })
}

/// Flat CLI-side view over the opaque [`TaskRunSnapshot`]; rendering works on
/// this DTO so the full state matrix stays testable without a runtime server.
struct TaskRunView {
    task_run_id: String,
    state: &'static str,
    stream_version: u64,
    active_attempt_id: Option<String>,
    terminal_result: Option<TaskTerminalResultView>,
}

struct TaskTerminalResultView {
    outcome: &'static str,
    reason: Option<String>,
}

impl TaskRunView {
    fn from_snapshot(snapshot: &TaskRunSnapshot) -> Self {
        Self {
            task_run_id: snapshot.task_run_id().to_string(),
            state: task_state_name(snapshot.state()),
            stream_version: snapshot.stream_version(),
            active_attempt_id: snapshot.active_attempt_id().map(|id| id.to_string()),
            terminal_result: snapshot.terminal_result().map(|result| match result {
                TaskRunTerminalResult::Success => TaskTerminalResultView {
                    outcome: "success",
                    reason: None,
                },
                TaskRunTerminalResult::Failure { reason } => TaskTerminalResultView {
                    outcome: "failure",
                    reason: Some(reason.clone()),
                },
            }),
        }
    }
}

/// Exhaustive `snake_case` naming of every `TaskRunState` variant; the missing
/// wildcard arm makes a new runtime state a compile error here on purpose.
const fn task_state_name(state: TaskRunState) -> &'static str {
    match state {
        TaskRunState::Created => "created",
        TaskRunState::Queued => "queued",
        TaskRunState::Admitted => "admitted",
        TaskRunState::Running => "running",
        TaskRunState::Waiting => "waiting",
        TaskRunState::Retrying => "retrying",
        TaskRunState::Checkpointing => "checkpointing",
        TaskRunState::Cancelling => "cancelling",
        TaskRunState::Reconciling => "reconciling",
        TaskRunState::Succeeded => "succeeded",
        TaskRunState::Failed => "failed",
        TaskRunState::Cancelled => "cancelled",
        TaskRunState::BudgetExhausted => "budget_exhausted",
        TaskRunState::PolicyDenied => "policy_denied",
        TaskRunState::Unrecoverable => "unrecoverable",
    }
}

/// Human-readable terminal result column: `-`, `success`, or `failure: reason`.
fn terminal_result_text(result: Option<&TaskTerminalResultView>) -> String {
    let Some(result) = result else {
        return "-".to_owned();
    };
    result
        .reason
        .as_deref()
        .map_or_else(|| result.outcome.to_owned(), |reason| {
            format!("failure: {reason}")
        })
}

/// One TAB-separated row per task run: id, state, stream version, active
/// attempt, terminal result. An empty list renders as a single sentence.
fn format_task_list_text(views: &[TaskRunView]) -> String {
    if views.is_empty() {
        return "no task runs".to_owned();
    }
    views
        .iter()
        .map(|view| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                view.task_run_id,
                view.state,
                view.stream_version,
                view.active_attempt_id.as_deref().unwrap_or("-"),
                terminal_result_text(view.terminal_result.as_ref()),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Five-line block for a single task run snapshot.
fn format_task_get_text(view: &TaskRunView) -> String {
    format!(
        "task run {}\nstate: {}\nstream version: {}\nactive attempt: {}\nterminal result: {}",
        view.task_run_id,
        view.state,
        view.stream_version,
        view.active_attempt_id.as_deref().unwrap_or("-"),
        terminal_result_text(view.terminal_result.as_ref()),
    )
}

fn terminal_result_json(result: &TaskTerminalResultView) -> serde_json::Value {
    match result.outcome {
        "success" => serde_json::json!({ "type": "success" }),
        _ => serde_json::json!({ "type": "failure", "reason": result.reason }),
    }
}

/// Typed JSON payload for one snapshot; mirrors the runtime wire contract
/// (camelCase keys always present, terminal result internally tagged by `type`).
fn task_run_json(view: &TaskRunView) -> serde_json::Value {
    serde_json::json!({
        "taskRunId": view.task_run_id,
        "state": view.state,
        "streamVersion": view.stream_version,
        "activeAttemptId": view.active_attempt_id,
        "terminalResult": view.terminal_result.as_ref().map(terminal_result_json),
    })
}

#[must_use]
fn task_list_json_data(views: &[TaskRunView]) -> serde_json::Value {
    serde_json::json!({
        "taskRuns": views.iter().map(task_run_json).collect::<Vec<_>>(),
    })
}

#[must_use]
fn task_get_json_data(view: &TaskRunView) -> serde_json::Value {
    task_run_json(view)
}
