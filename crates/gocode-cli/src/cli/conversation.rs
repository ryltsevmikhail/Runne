async fn run(arguments: Vec<OsString>) -> Result<String, CliError> {
    let mut arguments = VecDeque::from(arguments);
    if peek(&arguments) == Some("provider") {
        return run_provider_credential(arguments);
    }
    let profile_path = if peek(&arguments) == Some("--profile") {
        let _ = arguments.pop_front();
        PathBuf::from(arguments.pop_front().ok_or(CliError::Usage)?)
    } else {
        default_local_profile_path().map_err(|_| CliError::Profile)?
    };
    expect_token(&mut arguments, "conversation")?;
    let operation = pop_string(&mut arguments)?;
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
            serde_json::to_string(&messages).map_err(|_| CliError::Runtime)
        }
    }
}

fn new_command_identity() -> Result<CommandIdentity, CliError> {
    let command_id = CanonicalId::now_v7();
    CommandIdentity::new(command_id, command_id.to_string()).map_err(CliError::Api)
}

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
