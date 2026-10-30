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
#[cfg(not(target_os = "macos"))]
use runne_secure_store::NativeProviderCredentialStore;
use runne_secure_store::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialStatus, ProviderCredentialStore, SecureStoreError,
};

/// Global CLI state parsed from arguments.
struct CliState {
    format: OutputFormat,
    arguments: Vec<OsString>,
}

#[cfg(target_os = "linux")]
#[path = "cli/chat_scope.rs"]
mod chat_scope;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// CLI process entry shared by the `runne` binary and the signed desktop host.
pub fn main_entry() -> ! {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "linux")]
    if let Err(error) = chat_scope::ensure(&arguments) {
        write_process_outcome(&ProcessOutcome {
            stdout: String::new(),
            stderr: format!("{error}\n"),
            exit_code: 1,
        });
    }
    let outcome = run_entrypoint(arguments);
    write_process_outcome(&outcome);
}

#[cfg(target_os = "linux")]
mod linux_cli_credential_host;

mod directory_scope;
mod secret_input;
mod state_dir;
mod tui;
pub mod tui_backend;

include!("cli/entrypoint.rs");

include!("cli/command_lifecycle.rs");

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

fn run_provider_credential(arguments: VecDeque<OsString>) -> Result<CommandOutput, CliError> {
    #[cfg(target_os = "macos")]
    let backend = runne_secure_store::MacOsPlainProviderCredentialStore::new();
    #[cfg(not(target_os = "macos"))]
    let backend = NativeProviderCredentialStore::new();
    run_provider_credential_with(
        arguments,
        &backend,
        &NativeCredentialIdentityResolver,
        cfg!(target_os = "macos"),
        &secret_input::read_provider_credential,
    )
}

/// Stores already-read material through the same native identity policy used by
/// the CLI command. The terminal frontend calls this when the signed desktop
/// host is not the current process, so activation stays explicitly separate.
#[cfg(target_os = "macos")]
pub(crate) fn store_provider_credential_material(
    id: ProviderCredentialId,
    material: &ProviderCredentialMaterial,
) -> Result<(), CliError> {
    let access = NativeCredentialIdentityResolver.resolve()?;
    let store = runne_secure_store::MacOsPlainProviderCredentialStore::new();
    store
        .store_provider_credential(id, material, &access)
        .map_err(|error| map_credential_error(&error))?;
    require_outcome(
        store
            .provider_credential_status(id, &access)
            .map(|status| match status {
                ProviderCredentialStatus::Configured => CredentialOutcome::Configured,
                ProviderCredentialStatus::Missing => CredentialOutcome::Missing,
                ProviderCredentialStatus::Unsupported => CredentialOutcome::Unsupported,
            }),
        CredentialOutcome::Configured,
    )
}

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
