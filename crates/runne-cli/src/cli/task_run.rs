// Headless `exec` command: submit one TaskRun through the X2 typed lifecycle,
// stream state events, and exit by the exact terminal outcome. The CLI stores
// nothing: no session registry, no cursor, no raw HTTP or SQLite access.

/// Bounded wait for the terminal outcome; expiry is the typed `task_uncertain`
/// outcome, never a success claim.
const EXEC_TERMINAL_WAIT: Duration = std::time::Duration::from_secs(10);
const EXEC_POLL_INTERVAL: Duration = std::time::Duration::from_millis(200);

struct ExecCommand {
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    prompt: Option<String>,
    model: Option<String>,
}

fn parse_exec(mut arguments: VecDeque<OsString>) -> Result<ExecCommand, CliError> {
    let mut conversation_id = None;
    let mut workspace_id = None;
    let mut prompt = None;
    let mut model = None;

    while let Some(arg) = arguments.pop_front() {
        match arg.to_str() {
            Some("--help" | "-h") => return Err(CliError::Help(EXEC_HELP.to_owned())),
            Some("--conversation-id") => {
                conversation_id = Some(parse_id(&pop_string(&mut arguments)?)?);
            }
            Some("--workspace-id") => {
                workspace_id = Some(parse_id(&pop_string(&mut arguments)?)?);
            }
            Some("--prompt") => prompt = Some(pop_string(&mut arguments)?),
            Some("--model") => model = Some(pop_string(&mut arguments)?),
            _ => return Err(CliError::Usage),
        }
    }

    Ok(ExecCommand {
        conversation_id: conversation_id.ok_or(CliError::Usage)?,
        workspace_id: workspace_id.ok_or(CliError::Usage)?,
        prompt,
        model,
    })
}

/// The prompt comes from `--prompt` or, in the headless non-TTY path, from
/// piped stdin. A TTY stdin has no headless interaction path, so it is a typed
/// usage error, never a hidden prompt.
fn resolve_exec_prompt(prompt: Option<String>) -> Result<String, CliError> {
    if let Some(prompt) = prompt {
        return Ok(prompt);
    }
    if std::io::stdin().is_terminal() {
        return Err(CliError::Usage);
    }
    let mut piped = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut piped)
        .map_err(|_| CliError::Usage)?;
    let trimmed = piped.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(CliError::Usage);
    }
    Ok(trimmed.to_owned())
}

async fn run_exec(
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
    format: OutputFormat,
) -> Result<CommandOutput, CliError> {
    let command = parse_exec(arguments)?;
    let prompt = resolve_exec_prompt(command.prompt)?;

    let profile_path = profile_path
        .or_else(|| default_local_profile_path().ok())
        .ok_or(CliError::Profile)?;
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

    let request = SubmitTaskRunRequest::new(
        new_command_identity()?,
        command.conversation_id,
        command.workspace_id,
        prompt,
    )
    .map_err(CliError::Api)?;
    let request = match command.model {
        Some(model) => request.with_model(model),
        None => request,
    };
    let acknowledgement = client.submit_task_run(request).await.map_err(CliError::Api)?;

    let task_run_id = acknowledgement.task_run_id();
    let mut events = vec![serde_json::json!({
        "type": "submitted",
        "taskRunId": task_run_id.to_string(),
        "streamVersion": acknowledgement.stream_version(),
    })];

    let deadline = tokio::time::Instant::now() + EXEC_TERMINAL_WAIT;
    let mut observed_stream_version = acknowledgement.stream_version();
    let mut observed_state = Option::<TaskRunState>::None;
    let snapshot = loop {
        let snapshot = client.get_task_run(task_run_id).await.map_err(CliError::Api)?;
        if snapshot.stream_version() != observed_stream_version {
            observed_stream_version = snapshot.stream_version();
            if observed_state.is_none_or(|previous| previous != snapshot.state()) {
                observed_state = Some(snapshot.state());
                events.push(state_event(&snapshot));
            }
        } else if observed_state.is_none() {
            observed_state = Some(snapshot.state());
            events.push(state_event(&snapshot));
        }
        if is_terminal_state(snapshot.state()) {
            break snapshot;
        }
        if tokio::time::Instant::now() + EXEC_POLL_INTERVAL > deadline {
            let output = exec_output(&events, None, format);
            return Err(CliError::TaskUncertain(output));
        }
        tokio::time::sleep(EXEC_POLL_INTERVAL).await;
    };

    events.push(terminal_event(&snapshot));
    let output = exec_output(&events, Some(&snapshot), format);
    if snapshot.state() == TaskRunState::Succeeded {
        Ok(output)
    } else {
        Err(CliError::TaskNonHealthy(output))
    }
}

/// Renders the observed event stream for all three formats; the terminal
/// snapshot (when reached) contributes the text/json summary.
fn exec_output(
    events: &[serde_json::Value],
    snapshot: Option<&TaskRunSnapshot>,
    format: OutputFormat,
) -> CommandOutput {
    let events = events.to_vec();
    match format {
        OutputFormat::Jsonl => CommandOutput::Jsonl(events),
        OutputFormat::Json => CommandOutput::typed(
            snapshot.map(exec_summary_text).unwrap_or_default(),
            serde_json::json!({ "events": events }),
        ),
        OutputFormat::Text => CommandOutput::text(
            snapshot.map_or_else(|| "no terminal outcome".to_owned(), exec_summary_text),
        ),
    }
}

fn state_event(snapshot: &TaskRunSnapshot) -> serde_json::Value {
    serde_json::json!({
        "type": "state",
        "taskRunId": snapshot.task_run_id().to_string(),
        "state": task_state_name(snapshot.state()),
        "streamVersion": snapshot.stream_version(),
    })
}

fn terminal_event(snapshot: &TaskRunSnapshot) -> serde_json::Value {
    serde_json::json!({
        "type": "terminal",
        "taskRunId": snapshot.task_run_id().to_string(),
        "state": task_state_name(snapshot.state()),
        "streamVersion": snapshot.stream_version(),
        "terminalResult": snapshot.terminal_result().map(terminal_result_json),
    })
}

const fn is_terminal_state(state: TaskRunState) -> bool {
    matches!(
        state,
        TaskRunState::Succeeded
            | TaskRunState::Failed
            | TaskRunState::Cancelled
            | TaskRunState::BudgetExhausted
            | TaskRunState::PolicyDenied
            | TaskRunState::Unrecoverable
    )
}

fn exec_summary_text(snapshot: &TaskRunSnapshot) -> String {
    format!(
        "task run {}\nstate: {}\nterminal result: {}",
        snapshot.task_run_id(),
        task_state_name(snapshot.state()),
        terminal_result_text(snapshot.terminal_result()),
    )
}
