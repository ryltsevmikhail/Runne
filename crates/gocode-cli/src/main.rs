use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::io::{IsTerminal as _, Read};
use std::path::PathBuf;
use std::time::Duration;

use gocode_runtime_client::{
    CanonicalId, CommandIdentity, CreateConversationRequest, GenerateTextRequest,
    LocalProfileError, LocalRuntimeProfile, RuntimeApiError, default_local_profile_path,
};
use gocode_secure_store::{
    MAX_PROVIDER_CREDENTIAL_BYTES, NativeProviderCredentialStore, ProviderCredentialAccessPolicy,
    ProviderCredentialId, ProviderCredentialMaterial, ProviderCredentialStatus,
    ProviderCredentialStore, SecureStoreError,
};
use zeroize::Zeroize as _;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const USAGE: &str = "\
Usage:
  gocode [--profile PATH] conversation create [--workspace-id UUID]
  gocode [--profile PATH] conversation send --conversation-id UUID --expected-version N --text TEXT
  gocode [--profile PATH] conversation messages --conversation-id UUID";

#[tokio::main]
async fn main() {
    let outcome = process_outcome(run(std::env::args_os().skip(1).collect()).await);
    write_process_outcome(&outcome);
}

pub struct ProcessOutcome {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

fn process_outcome(result: Result<String, CliError>) -> ProcessOutcome {
    match result {
        Ok(stdout) => ProcessOutcome {
            stdout: format!("{stdout}\n"),
            stderr: String::new(),
            exit_code: 0,
        },
        Err(error) => ProcessOutcome {
            stdout: String::new(),
            stderr: format!("{error}\n"),
            exit_code: error.exit_code(),
        },
    }
}

pub fn write_process_outcome(outcome: &ProcessOutcome) -> ! {
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(outcome.stdout.as_bytes());
    let _ = std::io::stderr().write_all(outcome.stderr.as_bytes());
    std::process::exit(outcome.exit_code);
}

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

fn run_provider_credential(arguments: VecDeque<OsString>) -> Result<String, CliError> {
    let mut backend = NativeProviderCredentialStore::new();
    run_provider_credential_with(
        arguments,
        &mut std::io::stdin(),
        std::io::stdin().is_terminal(),
        &mut backend,
        &NativeCredentialIdentityResolver,
        cfg!(target_os = "macos"),
    )
}

fn run_provider_credential_with(
    arguments: VecDeque<OsString>,
    stdin: &mut impl Read,
    stdin_is_terminal: bool,
    backend: &mut impl CredentialBackend,
    resolver: &impl CredentialIdentityResolver,
    native_backend_supported: bool,
) -> Result<String, CliError> {
    let command = parse_provider_credential(arguments)?;
    execute_provider_credential_on_platform(
        command,
        stdin,
        stdin_is_terminal,
        backend,
        resolver,
        native_backend_supported,
    )
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderCredentialCommand {
    Set,
    Status,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialOutcome {
    Configured,
    Missing,
    Unsupported,
}

impl CredentialOutcome {
    const fn stdout(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Missing => "missing",
            Self::Unsupported => "unsupported",
        }
    }
}

trait CredentialBackend {
    fn status(
        &self,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError>;
    fn store(
        &mut self,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
    fn delete(&mut self) -> Result<(), SecureStoreError>;
}

impl<T: ProviderCredentialStore> CredentialBackend for T {
    fn status(
        &self,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        self.provider_credential_status(ProviderCredentialId::OpenAi, access)
            .map(|status| match status {
                ProviderCredentialStatus::Configured => CredentialOutcome::Configured,
                ProviderCredentialStatus::Missing => CredentialOutcome::Missing,
                ProviderCredentialStatus::Unsupported => CredentialOutcome::Unsupported,
            })
    }

    fn store(
        &mut self,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.store_provider_credential(ProviderCredentialId::OpenAi, credential, access)
    }

    fn delete(&mut self) -> Result<(), SecureStoreError> {
        self.delete_provider_credential(ProviderCredentialId::OpenAi)
    }
}

trait CredentialIdentityResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError>;
}

struct NativeCredentialIdentityResolver;

impl CredentialIdentityResolver for NativeCredentialIdentityResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        #[cfg(target_os = "macos")]
        {
            let writer = std::env::current_exe().map_err(|_| CliError::CredentialOperation)?;
            let writer =
                std::fs::canonicalize(writer).map_err(|_| CliError::CredentialOperation)?;
            let reader = writer
                .parent()
                .map(|directory| directory.join("gocoded"))
                .ok_or(CliError::CredentialOperation)?;
            ProviderCredentialAccessPolicy::new(&writer, &reader)
                .map_err(|_| CliError::CredentialOperation)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(CliError::UnsupportedCredentialBackend)
        }
    }
}

fn parse_provider_credential(
    mut arguments: VecDeque<OsString>,
) -> Result<ProviderCredentialCommand, CliError> {
    expect_token(&mut arguments, "provider")?;
    expect_token(&mut arguments, "credential")?;
    let operation = pop_string(&mut arguments)?;
    let command = match operation.as_str() {
        "set" => {
            parse_openai_provider(&mut arguments)?;
            expect_token(&mut arguments, "--stdin")?;
            ProviderCredentialCommand::Set
        }
        "status" => {
            parse_openai_provider(&mut arguments)?;
            ProviderCredentialCommand::Status
        }
        "delete" => {
            parse_openai_provider(&mut arguments)?;
            ProviderCredentialCommand::Delete
        }
        _ => return Err(CliError::Usage),
    };
    expect_end(&arguments)?;
    Ok(command)
}

fn parse_openai_provider(arguments: &mut VecDeque<OsString>) -> Result<(), CliError> {
    expect_token(arguments, "--provider")?;
    expect_token(arguments, "openai")
}

fn execute_provider_credential_on_platform(
    command: ProviderCredentialCommand,
    stdin: &mut impl Read,
    stdin_is_terminal: bool,
    backend: &mut impl CredentialBackend,
    resolver: &impl CredentialIdentityResolver,
    native_backend_supported: bool,
) -> Result<String, CliError> {
    match command {
        ProviderCredentialCommand::Set => {
            let credential = read_credential_bytes(stdin, stdin_is_terminal)?;
            if !native_backend_supported {
                return Ok(CredentialOutcome::Unsupported.stdout().to_owned());
            }
            let access = resolver.resolve()?;
            match backend.store(&credential, &access) {
                Ok(()) => Ok(CredentialOutcome::Configured.stdout().to_owned()),
                Err(
                    SecureStoreError::UnsupportedSecureStoreBackend | SecureStoreError::Unavailable,
                ) => Ok(CredentialOutcome::Unsupported.stdout().to_owned()),
                Err(error) => Err(map_credential_error(&error)),
            }
        }
        ProviderCredentialCommand::Status => {
            if !native_backend_supported {
                return Ok(CredentialOutcome::Unsupported.stdout().to_owned());
            }
            let access = resolver.resolve()?;
            backend
                .status(&access)
                .map(|outcome| outcome.stdout().to_owned())
                .map_err(|error| map_credential_error(&error))
        }
        ProviderCredentialCommand::Delete => {
            if !native_backend_supported {
                return Ok(CredentialOutcome::Unsupported.stdout().to_owned());
            }
            match backend.delete() {
                Ok(()) => Ok(CredentialOutcome::Missing.stdout().to_owned()),
                Err(
                    SecureStoreError::UnsupportedSecureStoreBackend | SecureStoreError::Unavailable,
                ) => Ok(CredentialOutcome::Unsupported.stdout().to_owned()),
                Err(error) => Err(map_credential_error(&error)),
            }
        }
    }
}

fn read_credential_bytes(
    stdin: &mut impl Read,
    stdin_is_terminal: bool,
) -> Result<ProviderCredentialMaterial, CliError> {
    if stdin_is_terminal {
        return Err(CliError::CredentialInput);
    }
    let mut bytes = Vec::with_capacity(MAX_PROVIDER_CREDENTIAL_BYTES.saturating_add(1));
    let mut bounded = stdin.take((MAX_PROVIDER_CREDENTIAL_BYTES + 1) as u64);
    if bounded.read_to_end(&mut bytes).is_err() || bytes.len() > MAX_PROVIDER_CREDENTIAL_BYTES {
        bytes.zeroize();
        return Err(CliError::CredentialInput);
    }
    ProviderCredentialMaterial::new(bytes).map_err(|_| CliError::CredentialInput)
}

const fn map_credential_error(error: &SecureStoreError) -> CliError {
    match error {
        SecureStoreError::UnsupportedSecureStoreBackend | SecureStoreError::Unavailable => {
            CliError::UnsupportedCredentialBackend
        }
        _ => CliError::CredentialOperation,
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod credential_test_support {
    use super::*;

    pub struct ProcessResult {
        pub outcome: ProcessOutcome,
        pub delete_calls: usize,
        pub resolver_calls: usize,
        pub store_calls: usize,
        pub store_received_stdin_secret: bool,
    }

    pub fn run(
        arguments: Vec<OsString>,
        stdin: &mut impl Read,
        stdin_is_terminal: bool,
        scenario: &str,
    ) -> ProcessResult {
        let mut backend = Backend {
            configured: scenario == "status",
            failure: scenario == "backend-error" || scenario == "set-backend-error",
            delete_calls: 0,
            store_calls: 0,
            store_received_stdin_secret: false,
        };
        let resolver = Resolver {
            fail: scenario == "resolver-error"
                || scenario == "set-resolver-error"
                || scenario == "delete",
            calls: std::cell::Cell::new(0),
        };
        let result = run_provider_credential_with(
            VecDeque::from(arguments),
            stdin,
            stdin_is_terminal,
            &mut backend,
            &resolver,
            true,
        );
        ProcessResult {
            outcome: process_outcome(result),
            delete_calls: backend.delete_calls,
            resolver_calls: resolver.calls.get(),
            store_calls: backend.store_calls,
            store_received_stdin_secret: backend.store_received_stdin_secret,
        }
    }

    struct Resolver {
        fail: bool,
        calls: std::cell::Cell<usize>,
    }

    impl CredentialIdentityResolver for Resolver {
        fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err(CliError::CredentialOperation);
            }
            let current = std::env::current_exe().map_err(|_| CliError::CredentialOperation)?;
            ProviderCredentialAccessPolicy::new(&current, &current)
                .map_err(|_| CliError::CredentialOperation)
        }
    }

    struct Backend {
        configured: bool,
        failure: bool,
        delete_calls: usize,
        store_calls: usize,
        store_received_stdin_secret: bool,
    }

    impl CredentialBackend for Backend {
        fn status(
            &self,
            _access: &ProviderCredentialAccessPolicy,
        ) -> Result<CredentialOutcome, SecureStoreError> {
            if self.failure {
                return Err(SecureStoreError::OperationFailed(
                    "backend-detail".to_owned(),
                ));
            }
            Ok(if self.configured {
                CredentialOutcome::Configured
            } else {
                CredentialOutcome::Missing
            })
        }

        fn store(
            &mut self,
            credential: &ProviderCredentialMaterial,
            _access: &ProviderCredentialAccessPolicy,
        ) -> Result<(), SecureStoreError> {
            self.store_calls += 1;
            self.store_received_stdin_secret =
                credential.with_bytes(|bytes| bytes == b"stdin-secret");
            if self.failure {
                return Err(SecureStoreError::OperationFailed(
                    "backend-detail".to_owned(),
                ));
            }
            self.configured = true;
            Ok(())
        }

        fn delete(&mut self) -> Result<(), SecureStoreError> {
            self.delete_calls += 1;
            self.configured = false;
            Ok(())
        }
    }
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
    ProfileIncompatible,
    Runtime,
    Api(RuntimeApiError),
    CredentialInput,
    CredentialOperation,
    UnsupportedCredentialBackend,
}

impl CliError {
    const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage => 2,
            Self::Profile
            | Self::ProfileIncompatible
            | Self::Runtime
            | Self::Api(_)
            | Self::CredentialInput
            | Self::CredentialOperation
            | Self::UnsupportedCredentialBackend => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(USAGE),
            Self::Profile => formatter.write_str("local runtime profile is unavailable"),
            Self::ProfileIncompatible => {
                formatter.write_str("local runtime profile is incompatible")
            }
            Self::Runtime => formatter.write_str("runtime is unavailable"),
            Self::Api(error) => {
                write!(formatter, "{error}")?;
                if let Some(request_id) = error.request_id() {
                    write!(formatter, " (request {request_id})")?;
                }
                Ok(())
            }
            Self::CredentialInput => formatter.write_str("provider credential input is invalid"),
            Self::CredentialOperation => {
                formatter.write_str("provider credential operation failed")
            }
            Self::UnsupportedCredentialBackend => {
                formatter.write_str("provider credential backend is unsupported")
            }
        }
    }
}

#[cfg(test)]
mod provider_credential_tests {
    use super::*;

    #[test]
    fn credential_commands_accept_only_the_exact_openai_forms() {
        assert!(matches!(
            parse_provider_credential(args(&[
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--stdin"
            ])),
            Ok(ProviderCredentialCommand::Set)
        ));
        assert!(matches!(
            parse_provider_credential(args(&[
                "provider",
                "credential",
                "status",
                "--provider",
                "openai"
            ])),
            Ok(ProviderCredentialCommand::Status)
        ));
        assert!(matches!(
            parse_provider_credential(args(&[
                "provider",
                "credential",
                "delete",
                "--provider",
                "openai"
            ])),
            Ok(ProviderCredentialCommand::Delete)
        ));

        for invalid in [
            [
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--value",
            ]
            .as_slice(),
            [
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--env",
            ]
            .as_slice(),
            [
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--file",
            ]
            .as_slice(),
            ["provider", "credential", "set", "--provider", "openai"].as_slice(),
            ["provider", "credential", "status", "--provider", "other"].as_slice(),
        ] {
            assert!(parse_provider_credential(args(invalid)).is_err());
        }
    }

    #[test]
    fn credential_input_rejects_secret_shaped_invalid_bytes_and_bounds_reads() {
        for mut invalid in [b"".as_slice(), b"a\0b", b"a\rb", b"a\nb"] {
            assert!(read_credential_bytes(&mut invalid, false).is_err());
        }
        assert!(read_credential_bytes(&mut vec![b'a'; 4_097].as_slice(), false).is_err());
        assert!(read_credential_bytes(&mut vec![b'a'; 4_096].as_slice(), false).is_ok());
        assert!(read_credential_bytes(&mut b"credential".as_slice(), true).is_err());
    }

    #[test]
    fn credential_execution_uses_closed_outputs_and_redacts_backend_errors() {
        let resolver = FakeResolver;
        let mut backend = FakeBackend::default();
        assert_eq!(
            execute_provider_credential_on_platform(
                ProviderCredentialCommand::Set,
                &mut b"secret".as_slice(),
                false,
                &mut backend,
                &resolver,
                true,
            )
            .unwrap(),
            "configured"
        );
        assert_eq!(
            execute_provider_credential_on_platform(
                ProviderCredentialCommand::Status,
                &mut b"".as_slice(),
                false,
                &mut backend,
                &resolver,
                true,
            )
            .unwrap(),
            "configured"
        );
        assert_eq!(
            execute_provider_credential_on_platform(
                ProviderCredentialCommand::Delete,
                &mut b"".as_slice(),
                false,
                &mut backend,
                &resolver,
                true,
            )
            .unwrap(),
            "missing"
        );

        backend.failure = true;
        let error = execute_provider_credential_on_platform(
            ProviderCredentialCommand::Status,
            &mut b"sensitive-marker".as_slice(),
            false,
            &mut backend,
            &resolver,
            true,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "provider credential operation failed");
        assert!(!error.contains("sensitive-marker"));
        assert!(!error.contains("backend-detail"));
    }

    #[test]
    fn unsupported_backend_never_reports_persistence() {
        let mut backend = FakeBackend::unsupported();
        assert_eq!(
            execute_provider_credential_on_platform(
                ProviderCredentialCommand::Set,
                &mut b"secret".as_slice(),
                false,
                &mut backend,
                &FakeResolver,
                true,
            )
            .unwrap(),
            "unsupported"
        );
        assert!(!backend.configured);
    }

    #[test]
    fn unsupported_platform_validates_set_input_before_returning_unsupported() {
        let mut backend = FakeBackend::default();
        let resolver = FakeResolver;

        assert!(matches!(
            execute_provider_credential_on_platform(
                ProviderCredentialCommand::Set,
                &mut b"invalid\ncredential".as_slice(),
                false,
                &mut backend,
                &resolver,
                false,
            ),
            Err(CliError::CredentialInput)
        ));
        assert!(matches!(
            execute_provider_credential_on_platform(
                ProviderCredentialCommand::Set,
                &mut b"credential".as_slice(),
                true,
                &mut backend,
                &resolver,
                false,
            ),
            Err(CliError::CredentialInput)
        ));
        assert_eq!(
            execute_provider_credential_on_platform(
                ProviderCredentialCommand::Set,
                &mut vec![b'x'; 4_096].as_slice(),
                false,
                &mut backend,
                &resolver,
                false,
            )
            .unwrap(),
            "unsupported"
        );
        assert!(!backend.configured);
    }

    fn args(values: &[&str]) -> VecDeque<OsString> {
        values.iter().map(OsString::from).collect()
    }

    struct FakeResolver;

    impl CredentialIdentityResolver for FakeResolver {
        fn resolve(&self) -> Result<gocode_secure_store::ProviderCredentialAccessPolicy, CliError> {
            let current = std::env::current_exe().map_err(|_| CliError::CredentialOperation)?;
            gocode_secure_store::ProviderCredentialAccessPolicy::new(&current, &current)
                .map_err(|_| CliError::CredentialOperation)
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        configured: bool,
        unsupported: bool,
        failure: bool,
    }

    impl FakeBackend {
        fn unsupported() -> Self {
            Self {
                unsupported: true,
                ..Self::default()
            }
        }
    }

    impl CredentialBackend for FakeBackend {
        fn status(
            &self,
            _access: &gocode_secure_store::ProviderCredentialAccessPolicy,
        ) -> Result<CredentialOutcome, gocode_secure_store::SecureStoreError> {
            if self.failure {
                return Err(gocode_secure_store::SecureStoreError::OperationFailed(
                    "backend-detail".into(),
                ));
            }
            Ok(if self.unsupported {
                CredentialOutcome::Unsupported
            } else if self.configured {
                CredentialOutcome::Configured
            } else {
                CredentialOutcome::Missing
            })
        }

        fn store(
            &mut self,
            _credential: &gocode_secure_store::ProviderCredentialMaterial,
            _access: &gocode_secure_store::ProviderCredentialAccessPolicy,
        ) -> Result<(), gocode_secure_store::SecureStoreError> {
            if self.unsupported {
                return Err(gocode_secure_store::SecureStoreError::UnsupportedSecureStoreBackend);
            }
            self.configured = true;
            Ok(())
        }

        fn delete(&mut self) -> Result<(), gocode_secure_store::SecureStoreError> {
            self.configured = false;
            Ok(())
        }
    }
}
