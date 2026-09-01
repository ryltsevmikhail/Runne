use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::io::{IsTerminal as _, Read};
use std::path::PathBuf;
use std::time::Duration;

use runne_runtime_client::{
    CanonicalId, CommandIdentity, CreateConversationRequest, GenerateTextRequest,
    LocalProfileError, LocalRuntimeProfile, RuntimeApiError, default_local_profile_path,
};
use runne_secure_store::{
    NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialStatus, ProviderCredentialStore, SecureStoreError,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Global CLI state parsed from arguments.
struct CliState {
    format: OutputFormat,
    arguments: Vec<OsString>,
}

fn main() {
    let arguments = std::env::args_os().skip(1).collect();
    let outcome = run_entrypoint(arguments);
    write_process_outcome(&outcome);
}

fn run_entrypoint(arguments: Vec<OsString>) -> ProcessOutcome {
    if arguments
        .first()
        .is_some_and(|argument| argument == runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1)
    {
        return broker_process_outcome(run_provider_credential_broker(VecDeque::from(arguments)));
    }
    let result = tokio::runtime::Runtime::new()
        .map_or((Err(CliError::Runtime), OutputFormat::Text), |runtime| {
            runtime.block_on(run_after_broker_bootstrap(arguments))
        });
    process_outcome(result.0, result.1)
}

fn broker_process_outcome(result: Result<(), CliError>) -> ProcessOutcome {
    match result {
        Ok(()) => ProcessOutcome {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
        Err(error) => process_outcome(Err(error), OutputFormat::Text),
    }
}

async fn run_after_broker_bootstrap(
    arguments: Vec<OsString>,
) -> (Result<String, CliError>, OutputFormat) {
    match parse_global_options(arguments) {
        Ok(state) => {
            let format = state.format;
            (run(state.arguments, format).await, format)
        }
        Err(error) => (Err(error), OutputFormat::Text),
    }
}

fn parse_global_options(arguments: Vec<OsString>) -> Result<CliState, CliError> {
    let mut arguments = VecDeque::from(arguments);
    let mut format = None;
    let mut remaining = Vec::new();

    while let Some(arg) = arguments.pop_front() {
        if arg == "--format" {
            let value = arguments.pop_front().ok_or(CliError::Usage)?;
            let parsed = value
                .to_str()
                .and_then(OutputFormat::parse)
                .ok_or(CliError::Usage)?;
            if format.replace(parsed).is_some() {
                return Err(CliError::Usage);
            }
        } else if let Some(s) = arg.to_str() {
            if let Some(value) = s.strip_prefix("--format=") {
                let parsed = OutputFormat::parse(value).ok_or(CliError::Usage)?;
                if format.replace(parsed).is_some() {
                    return Err(CliError::Usage);
                }
            } else {
                remaining.push(arg);
            }
        } else {
            remaining.push(arg);
        }
    }

    Ok(CliState {
        format: format.unwrap_or_default(),
        arguments: remaining,
    })
}

pub struct ProcessOutcome {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

fn process_outcome(result: Result<String, CliError>, format: OutputFormat) -> ProcessOutcome {
    match result {
        Ok(stdout) => {
            let output = match format {
                OutputFormat::Text => format!("{stdout}\n"),
                OutputFormat::Json => {
                    let envelope = SuccessEnvelope::new(serde_json::json!({
                        "output": stdout
                    }));
                    format!("{}\n", serde_json::to_string(&envelope).unwrap_or_default())
                }
            };
            ProcessOutcome {
                stdout: output,
                stderr: String::new(),
                exit_code: 0,
            }
        }
        Err(error) => {
            let exit_code = error.exit_code();

            // Help and Version always go to stdout as text
            match &error {
                CliError::Help(_) | CliError::Version(_) => {
                    return ProcessOutcome {
                        stdout: format!("{error}\n"),
                        stderr: String::new(),
                        exit_code,
                    };
                }
                CliError::HealthNonHealthy(stdout) | CliError::DoctorNonHealthy(stdout) => {
                    let stdout = match format {
                        OutputFormat::Text => format!("{stdout}\n"),
                        OutputFormat::Json => {
                            let envelope = SuccessEnvelope::new(serde_json::json!({
                                "output": stdout
                            }));
                            format!("{}\n", serde_json::to_string(&envelope).unwrap_or_default())
                        }
                    };
                    return ProcessOutcome {
                        stdout,
                        stderr: String::new(),
                        exit_code,
                    };
                }
                _ => {}
            }

            let (stdout, stderr) = match format {
                OutputFormat::Text => (String::new(), format!("{error}\n")),
                OutputFormat::Json => {
                    let code = error.error_code().unwrap_or(ErrorCode::ApiError);
                    let envelope = ErrorEnvelope::new(code, error.to_string());
                    let json = serde_json::to_string(&envelope).unwrap_or_default();
                    (String::new(), format!("{json}\n"))
                }
            };

            ProcessOutcome {
                stdout,
                stderr,
                exit_code,
            }
        }
    }
}

pub fn write_process_outcome(outcome: &ProcessOutcome) -> ! {
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(outcome.stdout.as_bytes());
    let _ = std::io::stderr().write_all(outcome.stderr.as_bytes());
    std::process::exit(outcome.exit_code);
}

include!("cli/output.rs");
include!("cli/help.rs");
include!("cli/status.rs");
include!("cli/health.rs");
include!("cli/doctor.rs");
include!("cli/provider_readiness.rs");
include!("cli/provider_checks.rs");
include!("cli/format.rs");
include!("cli/completion.rs");
include!("cli/conversation.rs");
include!("cli/provider_credential.rs");
include!("cli/provider_credential_broker.rs");
include!("cli/parsing.rs");
include!("cli/token_parsing.rs");
include!("cli/error.rs");
// The macOS authority lifecycle (init/sign/rotate/backup/restore/trust-reset)
// is compiled only on macOS and under tests, but `execute_transport` returns
// `AuthorityUnavailable` for those commands until a reviewed hidden-input/TTY
// adapter lands (see authority/command.rs). The implementations are therefore
// reachable only from unit tests; silence the macOS non-test dead-code claim
// with the same expectation style used across the workspace.
#[cfg_attr(
    all(target_os = "macos", not(test)),
    expect(
        dead_code,
        reason = "macOS authority lifecycle is intentionally un-wired until a reviewed hidden-input adapter lands; exercised only from unit tests"
    )
)]
mod authority;
mod release;

#[cfg(test)]
pub mod credential_test_support;
#[cfg(test)]
mod provider_credential_legacy_tests;
#[cfg(test)]
mod provider_credential_tests;
