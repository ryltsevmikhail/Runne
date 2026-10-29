use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::io::{IsTerminal as _, Read};
use std::path::PathBuf;
use std::time::Duration;

use runne_runtime_client::{
    AuthenticatedRuntimeClient, CancelTaskRunRequest, CanonicalId, CommandIdentity,
    ConversationContextScope, CreateConversationRequest, GenerateTextRequest, LocalProfileError,
    LocalRuntimeProfile, RuntimeApiError, RuntimeApiErrorKind, SubmitTaskRunRequest,
    TaskRunSnapshot, TaskRunState, TaskRunSubmitAcknowledgement, TaskRunTerminalResult,
    default_local_profile_path,
};
use runne_secure_store::{
    NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialStatus, ProviderCredentialStore, SecureStoreError,
};

/// Global CLI state parsed from arguments.
struct CliState {
    format: OutputFormat,
    arguments: Vec<OsString>,
}

include!("cli/process_entry.rs");

#[cfg(target_os = "linux")]
mod linux_cli_credential_host;

mod directory_scope;
mod state_dir;
mod tui;
mod tui_backend;

fn run_entrypoint(arguments: Vec<OsString>) -> ProcessOutcome {
    if tui_backend::selected(&arguments) {
        return tui_backend::entry(arguments);
    }
    #[cfg(target_os = "linux")]
    if linux_cli_credential_host::selected(&arguments) {
        return linux_cli_credential_host::run();
    }
    #[cfg(all(target_os = "macos", feature = "persistent-reference-probe"))]
    if persistent_reference_probe::selected(&arguments) {
        return persistent_reference_probe::outcome();
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1)
    {
        return broker_process_outcome(run_provider_credential_broker(VecDeque::from(arguments)));
    }
    #[cfg(target_os = "linux")]
    if arguments
        .iter()
        .any(|argument| argument == "--protected-runtime-root")
    {
        return protected_runtime_ui::run(arguments);
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

include!("cli/command_lifecycle.rs");

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

fn process_outcome(
    result: Result<CommandOutput, CliError>,
    format: OutputFormat,
) -> ProcessOutcome {
    match result {
        Ok(output) => ProcessOutcome {
            stdout: render_command_output(&output, format),
            stderr: String::new(),
            exit_code: 0,
        },
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
                // Non-healthy reports always print the full report to stdout;
                // only the exit code signals the failing outcome.
                CliError::HealthNonHealthy(output)
                | CliError::DoctorNonHealthy(output)
                | CliError::TaskNonHealthy(output) => {
                    return ProcessOutcome {
                        stdout: render_command_output(output, format),
                        stderr: String::new(),
                        exit_code,
                    };
                }
                // The uncertain task outcome is lossless: the observed event
                // stream stays on stdout while the typed envelope goes to
                // stderr.
                CliError::TaskUncertain(output) | CliError::CancelPending(output) => {
                    let code = error.error_code().unwrap_or(ErrorCode::ApiError);
                    let envelope = ErrorEnvelope::new(code, error.to_string());
                    return ProcessOutcome {
                        stdout: render_command_output(output, format),
                        stderr: format!(
                            "{}\n",
                            serde_json::to_string(&envelope).unwrap_or_default()
                        ),
                        exit_code,
                    };
                }
                _ => {}
            }

            let (stdout, stderr) = match format {
                OutputFormat::Text => (String::new(), format!("{error}\n")),
                OutputFormat::Json | OutputFormat::Jsonl => {
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

/// The single render point for command output: each command payload is
/// rendered exactly once, either as text, as the typed `data` of the JSON
/// envelope, or as one JSON object per JSONL line.
fn render_command_output(output: &CommandOutput, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => format!("{}\n", output.render_text()),
        OutputFormat::Json => {
            let envelope = SuccessEnvelope::new(output.data_value());
            format!("{}\n", serde_json::to_string(&envelope).unwrap_or_default())
        }
        OutputFormat::Jsonl => match output {
            CommandOutput::Jsonl(lines) => {
                let mut rendered = String::new();
                for line in lines {
                    rendered.push_str(&serde_json::to_string(line).unwrap_or_default());
                    rendered.push('\n');
                }
                rendered
            }
            // A single-object payload stays one JSON document; JSONL clients
            // parse it as a one-line stream.
            other => format!(
                "{}\n",
                serde_json::to_string(&other.data_value()).unwrap_or_default()
            ),
        },
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
include!("cli/task.rs");
include!("cli/task_run.rs");
include!("cli/permissions.rs");
include!("cli/task_run_poll.rs");
include!("cli/session.rs");
include!("cli/task_help.rs");
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
#[cfg(all(target_os = "macos", feature = "persistent-reference-probe"))]
pub mod persistent_reference_probe;
mod release;

#[cfg(test)]
#[path = "cli/permissions/approval_recovery_tests.rs"]
mod approval_recovery_tests;
#[cfg(test)]
#[path = "cli/permissions/approval_response_tests.rs"]
mod approval_response_tests;
#[cfg(test)]
pub mod credential_test_support;
#[cfg(test)]
mod output_tests;
#[cfg(test)]
#[path = "cli/permissions/recovery_tests.rs"]
mod permissions_recovery_tests;
#[cfg(test)]
#[path = "cli/permissions/tests.rs"]
mod permissions_tests;
#[cfg(test)]
#[path = "cli/permissions/transport_tests.rs"]
mod permissions_transport_tests;
#[cfg(test)]
mod provider_credential_legacy_tests;
#[cfg(test)]
mod provider_credential_tests;
#[cfg(test)]
mod task_render_escape_tests;
#[cfg(test)]
mod task_render_tests;
