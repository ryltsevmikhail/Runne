// Headless `exec` command: submit one TaskRun through the X2 typed lifecycle,
// stream state events, and exit by the exact terminal outcome. The CLI stores
// nothing: no session registry, no cursor, no raw HTTP or SQLite access.

/// Bounded wait for the terminal outcome; expiry is the typed `task_uncertain`
/// outcome, never a success claim.
const EXEC_TERMINAL_WAIT: Duration = std::time::Duration::from_secs(10);
const EXEC_POLL_INTERVAL: Duration = std::time::Duration::from_millis(200);
/// Bounded wait after a cancellation request; expiry is the typed
/// `cancel_pending` outcome, never a "cancelled" claim.
const CANCEL_GRACE: Duration = std::time::Duration::from_secs(5);

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

/// Connects the session client, resolving the profile like every command.
async fn connect_exec_client(
    profile_path: Option<PathBuf>,
) -> Result<AuthenticatedRuntimeClient, CliError> {
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
    profile
        .connect(REQUEST_TIMEOUT)
        .await
        .map_err(|error| match error {
            runne_runtime_client::LocalRuntimeConnectError::Transport(_) => CliError::Runtime,
            runne_runtime_client::LocalRuntimeConnectError::Api(error) => CliError::Api(error),
        })
}

async fn run_exec(
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
    format: OutputFormat,
) -> Result<CommandOutput, CliError> {
    let command = parse_exec(arguments)?;
    let prompt = resolve_exec_prompt(command.prompt)?;
    let client = connect_exec_client(profile_path).await?;

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
    let mut events = Vec::new();
    record_event(
        &mut events,
        format,
        serde_json::json!({
            "type": "submitted",
            "taskRunId": task_run_id.to_string(),
            "streamVersion": acknowledgement.stream_version(),
        }),
    )?;

    let (snapshot, _sigints_received, mut events) =
        poll_until_terminal(&client, &acknowledgement, events, format).await?;


    record_event(&mut events, format, terminal_event(&snapshot))?;
    let output = exec_output(&events, Some(&snapshot), format);
    if snapshot.state() == TaskRunState::Succeeded {
        Ok(output)
    } else {
        Err(CliError::TaskNonHealthy(output))
    }
}

/// Writes one JSONL event to stdout immediately; headless consumers observe
/// the stream while the run is in flight, not after process exit.
fn write_jsonl_event(line: &serde_json::Value) -> Result<(), CliError> {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, line).map_err(|_| CliError::Runtime)?;
    stdout.write_all(b"\n").map_err(|_| CliError::Runtime)?;
    stdout.flush().map_err(|_| CliError::Runtime)
}

/// Records an event: buffered for the end-of-process render in text/json,
/// written immediately in JSONL.
fn record_event(
    events: &mut Vec<serde_json::Value>,
    format: OutputFormat,
    event: serde_json::Value,
) -> Result<(), CliError> {
    if format == OutputFormat::Jsonl {
        write_jsonl_event(&event)
    } else {
        events.push(event);
        Ok(())
    }
}


/// Polls the run until a terminal state, handling SIGINT: the first signal
/// issues one typed cancellation request and starts the grace window; the
/// second exits immediately without any terminal claim. Returns the terminal
/// snapshot, the signal count, and the buffered events.
async fn poll_until_terminal(
    client: &AuthenticatedRuntimeClient,
    acknowledgement: &TaskRunSubmitAcknowledgement,
    mut events: Vec<serde_json::Value>,
    format: OutputFormat,
) -> Result<(TaskRunSnapshot, u32, Vec<serde_json::Value>), CliError> {
    let task_run_id = acknowledgement.task_run_id();
    let Ok(mut sigint) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    else {
        return Err(CliError::Runtime);
    };
    let mut sigints_received = 0u32;
    let mut cancel_deadline = None::<tokio::time::Instant>;

    let deadline = tokio::time::Instant::now() + EXEC_TERMINAL_WAIT;
    let mut observed_stream_version = acknowledgement.stream_version();
    let mut observed_state = Option::<TaskRunState>::None;
    let snapshot = loop {
        let snapshot = tokio::select! {
            biased;
            _ = sigint.recv() => {
                sigints_received = sigints_received.saturating_add(1);
                if sigints_received > 1 {
                    // Escalation: exit immediately without any terminal claim.
                    std::process::exit(130);
                }
                cancel_deadline = Some(tokio::time::Instant::now() + CANCEL_GRACE);
                record_event(
                    &mut events,
                    format,
                    serde_json::json!({
                        "type": "cancelRequested",
                        "taskRunId": task_run_id.to_string(),
                    }),
                )?;
                let cancel_request = CancelTaskRunRequest::new(
                    new_command_identity()?,
                    task_run_id,
                    observed_stream_version,
                );
                match client.cancel_task_run(cancel_request).await {
                    Ok(ack) => {
                        record_event(
                            &mut events,
                            format,
                            serde_json::json!({
                                "type": "cancelAcknowledged",
                                "taskRunId": task_run_id.to_string(),
                                "streamVersion": ack.stream_version(),
                            }),
                        )?;
                    }
                    Err(_) => {
                        record_event(
                            &mut events,
                            format,
                            serde_json::json!({
                                "type": "cancelRequestFailed",
                                "taskRunId": task_run_id.to_string(),
                            }),
                        )?;
                    }
                }
                continue;
            }
            snapshot = client.get_task_run(task_run_id) => {
                snapshot.map_err(CliError::Api)?
            }
        };
        if snapshot.stream_version() != observed_stream_version {
            observed_stream_version = snapshot.stream_version();
            if observed_state.is_none_or(|previous| previous != snapshot.state()) {
                observed_state = Some(snapshot.state());
                record_event(&mut events, format, state_event(&snapshot))?;
            }
        } else if observed_state.is_none() {
            observed_state = Some(snapshot.state());
            record_event(&mut events, format, state_event(&snapshot))?;
        }
        if is_terminal_state(snapshot.state()) {
            break snapshot;
        }
        let wait_deadline = cancel_deadline.unwrap_or(deadline);
        if tokio::time::Instant::now() + EXEC_POLL_INTERVAL > wait_deadline {
            let output = exec_output(&events, None, format);
            return Err(if sigints_received > 0 {
                CliError::CancelPending(output)
            } else {
                CliError::TaskUncertain(output)
            });
        }
        tokio::time::sleep(EXEC_POLL_INTERVAL).await;
    };

    Ok((snapshot, sigints_received, events))
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
        // JSONL events were written incrementally; nothing remains to render.
        OutputFormat::Jsonl => CommandOutput::Jsonl(Vec::new()),
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
