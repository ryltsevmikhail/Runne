// `session list` and `resume`: headless session UX over the authoritative
// runtime surface. Sessions are derived from the runtime TaskRun list (the
// snapshot carries the conversation/workspace binding); the CLI stores no
// session registry and resume never creates a new TaskRun.

async fn run_session(
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
    format: OutputFormat,
) -> Result<CommandOutput, CliError> {
    if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
        return Err(CliError::Help(SESSION_HELP.to_owned()));
    }
    let mut arguments = arguments;
    let subcommand = pop_string(&mut arguments)?;
    if subcommand != "list" {
        return Err(CliError::Usage);
    }
    expect_end(&arguments)?;
    let client = connect_session_client(profile_path).await?;

    let snapshots = client.list_task_runs().await.map_err(CliError::Api)?;
    let sessions = derive_sessions(&snapshots);
    let mut lines = Vec::with_capacity(sessions.len());
    for session in &sessions {
        lines.push(serde_json::json!({
            "type": "session",
            "conversationId": session.conversation_id,
            "workspaceId": session.workspace_id,
            "taskRunCount": session.task_run_count,
            "lastState": session.last_state,
            "lastTerminalResult": session.last_terminal_result,
        }));
    }
    let output = match format {
        OutputFormat::Jsonl => CommandOutput::Jsonl(lines.clone()),
        OutputFormat::Json => CommandOutput::typed(
            session_summary_text(&sessions),
            serde_json::json!({ "sessions": lines }),
        ),
        OutputFormat::Text => CommandOutput::text(session_summary_text(&sessions)),
    };
    Ok(output)
}

struct SessionRow {
    conversation_id: String,
    workspace_id: Option<String>,
    task_run_count: usize,
    last_state: &'static str,
    last_terminal_result: Option<serde_json::Value>,
}

/// Groups the authoritative `TaskRun` list by conversation, preserving the
/// runtime order (first occurrence of each conversation).
fn derive_sessions(snapshots: &[TaskRunSnapshot]) -> Vec<SessionRow> {
    let mut order: Vec<String> = Vec::new();
    let mut grouped: std::collections::HashMap<String, Vec<&TaskRunSnapshot>> =
        std::collections::HashMap::new();
    for snapshot in snapshots {
        let Some(conversation_id) = snapshot.conversation_id().map(|id| id.to_string()) else {
            continue;
        };
        if !grouped.contains_key(&conversation_id) {
            order.push(conversation_id.clone());
        }
        grouped.entry(conversation_id).or_default().push(snapshot);
    }
    order
        .into_iter()
        .filter_map(|conversation_id| {
            let runs = grouped.remove(&conversation_id)?;
            let last = runs.last()?;
            Some(SessionRow {
                task_run_count: runs.len(),
                conversation_id,
                workspace_id: last.workspace_id().map(|id| id.to_string()),
                last_state: task_state_name(last.state()),
                last_terminal_result: last.terminal_result().map(terminal_result_json),
            })
        })
        .collect()
}

fn session_summary_text(sessions: &[SessionRow]) -> String {
    if sessions.is_empty() {
        return "no sessions".to_owned();
    }
    sessions
        .iter()
        .map(|session| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                session.conversation_id,
                session.workspace_id.as_deref().unwrap_or("-"),
                session.task_run_count,
                session.last_state,
                session
                    .last_terminal_result
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), std::string::ToString::to_string),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

struct ResumeCommand {
    conversation_id: Option<CanonicalId>,
    workspace_id: Option<CanonicalId>,
}

fn parse_resume(mut arguments: VecDeque<OsString>) -> Result<ResumeCommand, CliError> {
    let mut conversation_id = None;
    let mut last = false;
    let mut workspace_id = None;
    while let Some(arg) = arguments.pop_front() {
        match arg.to_str() {
            Some("--help" | "-h") => return Err(CliError::Help(RESUME_HELP.to_owned())),
            Some("--last") => last = true,
            Some("--workspace-id") => {
                workspace_id = Some(parse_id(&pop_string(&mut arguments)?)?);
            }
            Some(value) => {
                if conversation_id.is_some() {
                    return Err(CliError::Usage);
                }
                conversation_id = Some(parse_id(value)?);
            }
            None => return Err(CliError::Usage),
        }
    }
    if last && conversation_id.is_some() {
        return Err(CliError::Usage);
    }
    if !last && conversation_id.is_none() {
        return Err(CliError::Usage);
    }
    Ok(ResumeCommand {
        conversation_id,
        workspace_id,
    })
}

async fn run_resume(
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
    format: OutputFormat,
) -> Result<CommandOutput, CliError> {
    let command = parse_resume(arguments)?;
    let client = connect_session_client(profile_path).await?;

    let snapshots = client.list_task_runs().await.map_err(CliError::Api)?;
    let sessions = derive_sessions(&snapshots);
    let conversation_id = if let Some(id) = command.conversation_id {
        id
    } else {
        let workspace = command.workspace_id.map(|id| id.to_string());
        sessions
            .iter()
            .rev()
            .find(|session| {
                workspace.as_deref().is_none_or(|expected| {
                    session.workspace_id.as_deref() == Some(expected)
                })
            })
            .and_then(|session| parse_id(&session.conversation_id).ok())
            .ok_or(CliError::SessionNotFound)?
    };

    let session = sessions
        .iter()
        .find(|session| session.conversation_id == conversation_id.to_string())
        .ok_or(CliError::SessionNotFound)?;
    if let Some(expected) = command.workspace_id
        && session.workspace_id.as_deref() != Some(&expected.to_string())
    {
        return Err(CliError::SessionWorkspaceMismatch);
    }

    // The authoritative committed projection of the session: its messages
    // plus the durable terminal receipts of its task runs. No new TaskRun.
    let messages = client
        .list_messages(conversation_id)
        .await
        .map_err(CliError::Api)?;
    let runs: Vec<serde_json::Value> = snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.conversation_id().map(|id| id.to_string()).as_deref()
                == Some(conversation_id.to_string().as_str())
        })
        .map(|snapshot| {
            serde_json::json!({
                "taskRunId": snapshot.task_run_id().to_string(),
                "state": task_state_name(snapshot.state()),
                "streamVersion": snapshot.stream_version(),
                "terminalResult": snapshot.terminal_result().map(terminal_result_json),
            })
        })
        .collect();
    let data = serde_json::json!({
        "conversationId": conversation_id.to_string(),
        "workspaceId": session.workspace_id,
        "taskRuns": runs,
        "messages": messages_json_data(&messages),
    });
    let text = format!(
        "session {}\nworkspace: {}\ntask runs: {}\nmessages: {}",
        conversation_id,
        session.workspace_id.as_deref().unwrap_or("-"),
        runs.len(),
        messages.messages.len(),
    );
    Ok(match format {
        OutputFormat::Text => CommandOutput::text(text),
        OutputFormat::Json => CommandOutput::typed(text, data),
        OutputFormat::Jsonl => CommandOutput::Jsonl(vec![data]),
    })
}

async fn connect_session_client(
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
