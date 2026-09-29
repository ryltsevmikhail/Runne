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
    // The signal stream is installed BEFORE the submit so a SIGINT arriving
    // immediately after the submitted event can never hit the default
    // disposition (observed as a signal exit on slow hosted workers).
    let Ok(mut sigint) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    else {
        return Err(CliError::Runtime);
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
        poll_until_terminal(&client, &acknowledgement, events, format, &mut sigint).await?;


    record_event(&mut events, format, terminal_event(&snapshot))?;
    let output = exec_output(&events, Some(&snapshot), format);
    if snapshot.state() == TaskRunState::Succeeded {
        Ok(output)
    } else {
        Err(CliError::TaskNonHealthy(output))
    }
}
