use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use gocode_runtime_client::{
    CanonicalId, CommandIdentity, CreateConversationRequest, GenerateTextRequest,
    LocalRuntimeProfile, RuntimeApiError, default_local_profile_path,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const USAGE: &str = "\
Usage:
  gocode [--profile PATH] conversation create [--workspace-id UUID]
  gocode [--profile PATH] conversation send --conversation-id UUID --expected-version N --text TEXT
  gocode [--profile PATH] conversation messages --conversation-id UUID";

#[tokio::main]
async fn main() {
    match run(std::env::args_os().skip(1).collect()).await {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(error.exit_code());
        }
    }
}

async fn run(arguments: Vec<OsString>) -> Result<String, CliError> {
    let mut arguments = VecDeque::from(arguments);
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

    let profile = LocalRuntimeProfile::load(&profile_path).map_err(|_| CliError::Profile)?;
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

fn parse_create(mut arguments: VecDeque<OsString>) -> Result<ConversationCommand, CliError> {
    if arguments.is_empty() {
        return Ok(ConversationCommand::Create {
            workspace_id: CanonicalId::now_v7(),
        });
    }
    expect_token(&mut arguments, "--workspace-id")?;
    let workspace_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_end(&arguments)?;
    Ok(ConversationCommand::Create { workspace_id })
}

fn parse_send(mut arguments: VecDeque<OsString>) -> Result<ConversationCommand, CliError> {
    expect_token(&mut arguments, "--conversation-id")?;
    let conversation_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_token(&mut arguments, "--expected-version")?;
    let expected_version = pop_string(&mut arguments)?
        .parse()
        .map_err(|_| CliError::Usage)?;
    expect_token(&mut arguments, "--text")?;
    let text = pop_string(&mut arguments)?;
    expect_end(&arguments)?;
    Ok(ConversationCommand::Send {
        conversation_id,
        expected_version,
        text,
    })
}

fn parse_messages(mut arguments: VecDeque<OsString>) -> Result<ConversationCommand, CliError> {
    expect_token(&mut arguments, "--conversation-id")?;
    let conversation_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_end(&arguments)?;
    Ok(ConversationCommand::Messages { conversation_id })
}

fn parse_id(value: &str) -> Result<CanonicalId, CliError> {
    CanonicalId::parse(value).map_err(|_| CliError::Usage)
}

fn peek(arguments: &VecDeque<OsString>) -> Option<&str> {
    arguments.front().and_then(|value| value.to_str())
}

fn expect_token(arguments: &mut VecDeque<OsString>, expected: &str) -> Result<(), CliError> {
    let actual = pop_string(arguments)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CliError::Usage)
    }
}

fn pop_string(arguments: &mut VecDeque<OsString>) -> Result<String, CliError> {
    arguments
        .pop_front()
        .ok_or(CliError::Usage)?
        .into_string()
        .map_err(|_| CliError::Usage)
}

fn expect_end(arguments: &VecDeque<OsString>) -> Result<(), CliError> {
    if arguments.is_empty() {
        Ok(())
    } else {
        Err(CliError::Usage)
    }
}

#[derive(Debug)]
enum CliError {
    Usage,
    Profile,
    Runtime,
    Api(RuntimeApiError),
}

impl CliError {
    const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage => 2,
            Self::Profile | Self::Runtime | Self::Api(_) => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(USAGE),
            Self::Profile => formatter.write_str("local runtime profile is unavailable"),
            Self::Runtime => formatter.write_str("runtime is unavailable"),
            Self::Api(error) => {
                write!(formatter, "{error}")?;
                if let Some(request_id) = error.request_id() {
                    write!(formatter, " (request {request_id})")?;
                }
                Ok(())
            }
        }
    }
}
