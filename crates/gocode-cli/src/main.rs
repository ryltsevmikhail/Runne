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
  gocode [--profile PATH] conversation messages --conversation-id UUID
  gocode authority --help
  gocode release --help";

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

include!("cli/conversation.rs");
include!("cli/provider_credential.rs");
include!("cli/parsing.rs");
include!("cli/token_parsing.rs");
include!("cli/error.rs");
mod authority;
mod release;

#[cfg(test)]
pub mod credential_test_support;
#[cfg(test)]
mod provider_credential_tests;
