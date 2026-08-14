enum ConversationCommand {
    Create {
        workspace_id: CanonicalId,
    },
    Send {
        conversation_id: CanonicalId,
        expected_version: u64,
        text: String,
    },
    Messages {
        conversation_id: CanonicalId,
    },
}

fn check_top_level_flags(arguments: &mut VecDeque<OsString>) -> Result<(), CliError> {
    let first = peek(arguments);
    match first {
        Some("--help" | "-h") => {
            let _ = arguments.pop_front();
            Err(CliError::Help(TOP_LEVEL_HELP.to_owned()))
        }
        Some("--version" | "-V") => {
            let _ = arguments.pop_front();
            expect_end(arguments)?;
            Err(CliError::Version(version_string()))
        }
        _ => Ok(()),
    }
}

fn collect_help_path(arguments: &mut VecDeque<OsString>) -> Vec<&'static str> {
    let mut path = Vec::new();
    while let Some(arg) = arguments.pop_front() {
        if let Some(s) = arg.to_str() {
            // Leak the string to get a 'static reference (acceptable for help text)
            let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
            path.push(leaked);
        }
    }
    path
}

fn new_command_identity() -> Result<CommandIdentity, CliError> {
    let command_id = CanonicalId::now_v7();
    CommandIdentity::new(command_id, command_id.to_string()).map_err(CliError::Api)
}

async fn run(arguments: Vec<OsString>, format: OutputFormat) -> Result<String, CliError> {
    let mut arguments = VecDeque::from(arguments);
    
    // Check for top-level --help/-h/--version/-V before any command dispatch
    check_top_level_flags(&mut arguments)?;
    
    if peek(&arguments) == Some("provider") {
        return run_provider_credential(arguments);
    }
    
    if peek(&arguments) == Some("help") {
        let _ = arguments.pop_front();
        let command_path = collect_help_path(&mut arguments);
        return Err(CliError::Help(help_for(&command_path).to_owned()));
    }
    
    let profile_path = if peek(&arguments) == Some("--profile") {
        let _ = arguments.pop_front();
        Some(PathBuf::from(arguments.pop_front().ok_or(CliError::Usage)?))
    } else {
        None
    };
    
    let command_token = pop_string(&mut arguments)?;
    
    dispatch_command(command_token, profile_path, arguments, format).await
}

async fn dispatch_command(
    command: String,
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
    format: OutputFormat,
) -> Result<String, CliError> {
    match command.as_str() {
        "conversation" => run_conversation(profile_path, arguments, format).await,
        "status" => run_status_command(profile_path, arguments).await,
        "health" => run_health_command(profile_path, arguments).await,
        "doctor" => run_doctor_command(profile_path, arguments).await,
        "completion" => run_completion_command(arguments),
        _ => Err(CliError::Usage),
    }
}

async fn run_conversation(
    profile_path: Option<PathBuf>,
    mut arguments: VecDeque<OsString>,
    format: OutputFormat,
) -> Result<String, CliError> {
    let profile_path = profile_path
        .or_else(|| default_local_profile_path().ok())
        .ok_or(CliError::Profile)?;
    
    let operation = pop_string(&mut arguments)?;
    
    // Check for --help after subcommand
    if operation == "--help" || operation == "-h" {
        return Err(CliError::Help(CONVERSATION_HELP.to_owned()));
    }
    
    let command = match operation.as_str() {
        "create" => parse_create(arguments)?,
        "send" => parse_send(arguments)?,
        "messages" => parse_messages(arguments)?,
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
            gocode_runtime_client::LocalRuntimeConnectError::Transport(_) => CliError::Runtime,
            gocode_runtime_client::LocalRuntimeConnectError::Api(error) => CliError::Api(error),
        })?;

    match command {
        ConversationCommand::Create { workspace_id } => {
            let conversation_id = CanonicalId::now_v7();
            let created = client
                .create_conversation(CreateConversationRequest::new(
                    new_command_identity()?,
                    conversation_id,
                    workspace_id,
                ))
                .await
                .map_err(CliError::Api)?;
            Ok(created.conversation_id.to_string())
        }
        ConversationCommand::Send {
            conversation_id,
            expected_version,
            text,
        } => {
            let generated = client
                .generate_text(
                    GenerateTextRequest::new(
                        new_command_identity()?,
                        conversation_id,
                        expected_version,
                        text,
                    )
                    .map_err(CliError::Api)?,
                )
                .await
                .map_err(CliError::Api)?;
            Ok(generated.assistant_message.text)
        }
        ConversationCommand::Messages { conversation_id } => {
            let messages = client
                .list_messages(conversation_id)
                .await
                .map_err(CliError::Api)?;
            
            match format {
                OutputFormat::Text => Ok(format_messages_text(&messages)),
                OutputFormat::Json => Ok(format_messages_json(&messages)),
            }
        }
    }
}

async fn run_status_command(
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
) -> Result<String, CliError> {
    // Check for --help
    if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
        return Err(CliError::Help(STATUS_HELP.to_owned()));
    }
    expect_end(&arguments)?;
    let profile_path = profile_path
        .or_else(|| default_local_profile_path().ok())
        .ok_or(CliError::Profile)?;
    run_status_async(profile_path).await.map_err(|e| match e {
        StatusError::ProfileUnavailable => CliError::Profile,
        StatusError::ProfileIncompatible => CliError::ProfileIncompatible,
        StatusError::ConnectionFailed => CliError::Runtime,
    })
}

async fn run_health_command(
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
) -> Result<String, CliError> {
    // Check for --help
    if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
        return Err(CliError::Help(HEALTH_HELP.to_owned()));
    }
    expect_end(&arguments)?;
    let health_info = run_health(profile_path).await.map_err(|e| match e {
        HealthError::ProfileUnavailable => CliError::Profile,
        HealthError::ProfileIncompatible => CliError::ProfileIncompatible,
        HealthError::ConnectionFailed | HealthError::HealthCheckFailed => CliError::Runtime,
    })?;
    Ok(format_health(&health_info, OutputFormat::Text))
}

async fn run_doctor_command(
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
) -> Result<String, CliError> {
    // Check for --help
    if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
        return Err(CliError::Help(DOCTOR_HELP.to_owned()));
    }
    expect_end(&arguments)?;
    let report = run_doctor(profile_path).await?;
    let output = format_diagnostic_report(&report, OutputFormat::Text);
    
    // Return error if any check failed
    if report.overall_status == CheckStatus::Error {
        return Err(CliError::Runtime);
    }
    
    Ok(output)
}

fn run_completion_command(mut arguments: VecDeque<OsString>) -> Result<String, CliError> {
    // Check for --help
    if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
        return Err(CliError::Help(COMPLETION_HELP.to_owned()));
    }
    
    let shell_name = pop_string(&mut arguments)?;
    expect_end(&arguments)?;
    
    let shell = Shell::parse(&shell_name).ok_or(CliError::Usage)?;
    Ok(generate_completion(shell))
}
