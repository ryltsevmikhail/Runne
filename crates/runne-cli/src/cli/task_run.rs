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
    profile_id: Option<String>,
    profile_digest: Option<String>,
    local_executable: Option<runne_api::TaskRunExecutable>,
    command_cwd: Option<String>,
    command_args: Vec<String>,
    command_env: Vec<(String, String)>,
}

fn parse_exec(mut arguments: VecDeque<OsString>) -> Result<ExecCommand, CliError> {
    let mut conversation_id = None;
    let mut workspace_id = None;
    let mut prompt = None;
    let mut model = None;
    let mut profile_id = None;
    let mut profile_digest = None;
    let mut local_executable = None;
    let mut command_cwd = None;
    let mut command_args = Vec::new();
    let mut command_env = Vec::new();

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
            Some("--profile-id") => profile_id = Some(pop_string(&mut arguments)?),
            Some("--profile-digest") => profile_digest = Some(pop_string(&mut arguments)?),
            Some("--workspace-executable") => {
                if local_executable.is_some() {
                    return Err(CliError::Usage);
                }
                local_executable = Some(
                    runne_api::TaskRunExecutable::workspace_relative(pop_string(&mut arguments)?)
                        .map_err(|_| CliError::Usage)?,
                );
            }
            Some("--system-executable") => {
                if local_executable.is_some() {
                    return Err(CliError::Usage);
                }
                local_executable = Some(
                    runne_api::TaskRunExecutable::system_program(pop_string(&mut arguments)?)
                        .map_err(|_| CliError::Usage)?,
                );
            }
            Some("--cwd") => command_cwd = Some(pop_string(&mut arguments)?),
            Some("--arg") => command_args.push(pop_string(&mut arguments)?),
            Some("--env") => {
                let value = pop_string(&mut arguments)?;
                let (key, value) = value.split_once('=').ok_or(CliError::Usage)?;
                command_env.push((key.to_owned(), value.to_owned()));
            }
            _ => return Err(CliError::Usage),
        }
    }

    Ok(ExecCommand {
        conversation_id: conversation_id.ok_or(CliError::Usage)?,
        workspace_id: workspace_id.ok_or(CliError::Usage)?,
        prompt,
        model,
        profile_id,
        profile_digest,
        local_executable,
        command_cwd,
        command_args,
        command_env,
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
    if command.local_executable.is_some()
        && (command.model.is_some()
            || command.profile_id.is_some()
            || command.profile_digest.is_some())
    {
        return Err(CliError::Usage);
    }
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
        Some(model) => request.with_model(model).map_err(CliError::Api)?,
        None => request,
    };
    let request = match (command.profile_id, command.profile_digest) {
        (Some(id), Some(hex_digest)) => {
            let digest = parse_profile_digest(&hex_digest).ok_or(CliError::Usage)?;
            let selected =
                runne_api::SelectedProviderProfile::new(id, digest).map_err(|_| CliError::Usage)?;
            request
                .with_selected_profile(selected)
                .map_err(CliError::Api)?
        }
        (None, None) => request,
        _ => return Err(CliError::Usage),
    };
    let request = if let Some(executable) = command.local_executable {
        let mut argv = vec![executable.value().to_owned()];
        argv.extend(command.command_args);
        let local = runne_api::TaskRunLocalCommand::new(
            executable,
            command.command_cwd.unwrap_or_else(|| ".".to_owned()),
            argv,
            command.command_env,
        )
        .map_err(|_| CliError::Usage)?;
        request.with_local_command(local).map_err(CliError::Api)?
    } else {
        if command.command_cwd.is_some()
            || !command.command_args.is_empty()
            || !command.command_env.is_empty()
        {
            return Err(CliError::Usage);
        }
        request
    };
    // The signal stream is installed BEFORE the submit so a SIGINT arriving
    // immediately after the submitted event can never hit the default
    // disposition (observed as a signal exit on slow hosted workers).
    let Ok(mut sigint) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    else {
        return Err(CliError::Runtime);
    };
    let acknowledgement = client
        .submit_task_run(request)
        .await
        .map_err(CliError::Api)?;

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
    if exec_terminal_is_success(snapshot.state(), snapshot.terminal_result()) {
        Ok(output)
    } else {
        Err(CliError::TaskNonHealthy(output))
    }
}

fn exec_terminal_is_success(state: TaskRunState, result: Option<&TaskRunTerminalResult>) -> bool {
    state == TaskRunState::Succeeded && matches!(result, Some(TaskRunTerminalResult::Success))
}

fn parse_profile_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

#[cfg(test)]
mod local_result_tests {
    use super::*;

    #[test]
    fn exit_code_tracks_terminal_result_even_when_task_state_is_succeeded() {
        assert!(exec_terminal_is_success(
            TaskRunState::Succeeded,
            Some(&TaskRunTerminalResult::Success)
        ));
        let failure = TaskRunTerminalResult::Failure {
            reason: "local_command_exit_7".to_owned(),
        };
        assert!(!exec_terminal_is_success(
            TaskRunState::Succeeded,
            Some(&failure)
        ));
        let output = CommandOutput::Jsonl(vec![serde_json::json!({
            "type": "terminal",
            "state": "succeeded",
            "terminalResult": { "kind": "failure", "reason": "local_command_exit_7" },
        })]);
        let result = if exec_terminal_is_success(TaskRunState::Succeeded, Some(&failure)) {
            Ok(output)
        } else {
            Err(CliError::TaskNonHealthy(output))
        };
        let process = process_outcome(result, OutputFormat::Jsonl);
        assert_ne!(process.exit_code, 0);
        assert!(process.stdout.contains("local_command_exit_7"));
        assert!(!exec_terminal_is_success(TaskRunState::Succeeded, None));
        assert!(!exec_terminal_is_success(
            TaskRunState::Failed,
            Some(&TaskRunTerminalResult::Success)
        ));
    }
}
