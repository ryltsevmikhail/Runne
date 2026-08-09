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

/// Global CLI state parsed from arguments.
struct CliState {
    format: OutputFormat,
    arguments: Vec<OsString>,
}

#[tokio::main]
async fn main() {
    let state = parse_global_options(std::env::args_os().skip(1).collect());
    let format = state.format;
    let outcome = process_outcome(run(state.arguments).await, format);
    write_process_outcome(&outcome);
}

fn parse_global_options(arguments: Vec<OsString>) -> CliState {
    let mut arguments = VecDeque::from(arguments);
    let mut format = OutputFormat::Text;
    let mut remaining = Vec::new();

    while let Some(arg) = arguments.pop_front() {
        if arg == "--format" {
            if let Some(value) = arguments.pop_front()
                && let Some(f) = value.to_str().and_then(OutputFormat::parse)
            {
                format = f;
            }
        } else if let Some(s) = arg.to_str() {
            if let Some(value) = s.strip_prefix("--format=") {
                if let Some(f) = OutputFormat::parse(value) {
                    format = f;
                }
            } else {
                remaining.push(arg);
            }
        } else {
            remaining.push(arg);
        }
    }

    CliState {
        format,
        arguments: remaining,
    }
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
include!("cli/format.rs");
include!("cli/completion.rs");
include!("cli/conversation.rs");
include!("cli/provider_credential.rs");
include!("cli/parsing.rs");
include!("cli/error.rs");

#[cfg(test)]
pub mod credential_test_support;
#[cfg(test)]
mod provider_credential_tests;
