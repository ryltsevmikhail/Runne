#[path = "provider_credential_support/cases.rs"]
mod provider_credential_cases;
use provider_credential_cases::CHILD_CASES;

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Write as _;
use std::io::{IsTerminal as _, Read};
use std::process::{Command, Stdio};

use runne_secure_store::{
    NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialStatus, ProviderCredentialStore, SecureStoreError,
};

const TEST_USAGE: &str = "\
Runne command-line interface.

Usage:
  runne [options] <command> [<args>]
  runne help [<command>]
  runne authority --help
  runne release --help

Options:
  -h, --help       Show this help message
  -V, --version    Show version information

Commands:
  conversation     Manage conversations
  provider         Manage provider credentials
  status           Show runtime connection status
  health           Check runtime health status
  doctor           Run comprehensive system diagnostics
  completion       Generate shell completion scripts
  authority        Manage project-owner authority
  release          Manage release authority

Run 'runne help <command>' for more information on a command.";

#[derive(Clone, Copy)]
enum OutputFormat {
    Text,
}

/// Mirror of the binary's typed command output; the credential surface only
/// produces plain text payloads.
enum CommandOutput {
    Text(String),
}

impl CommandOutput {
    fn text(payload: impl Into<String>) -> Self {
        Self::Text(payload.into())
    }
}

struct ProcessOutcome {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

fn process_outcome(result: Result<CommandOutput, CliError>, _: OutputFormat) -> ProcessOutcome {
    match result {
        Ok(CommandOutput::Text(text)) => ProcessOutcome {
            stdout: format!("{text}\n"),
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

include!("../src/cli/token_parsing.rs");
include!("../src/cli/help.rs");
include!("../src/cli/provider_credential.rs");

#[derive(Debug)]
enum CliError {
    Help(String),
    Usage,
    CredentialOperation,
    UnsupportedCredentialBackend,
}

impl CliError {
    const fn exit_code(&self) -> i32 {
        match self {
            Self::Help(_) => 0,
            Self::Usage => 2,
            Self::CredentialOperation | Self::UnsupportedCredentialBackend => 4,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Help(text) => text,
            Self::Usage => TEST_USAGE,
            Self::CredentialOperation => "provider credential operation failed",
            Self::UnsupportedCredentialBackend => "provider credential backend is unsupported",
        })
    }
}

#[path = "../src/credential_test_support.rs"]
mod credential_test_support;

fn main() {
    assert_eq!(peek(&VecDeque::new()), None);
    let _ = NativeCredentialIdentityResolver;
    let _ = run_provider_credential;
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--child")) {
        run_child(arguments.collect());
    }

    let delete = credential_test_support::run(
        ["provider", "credential", "delete", "--provider", "openai"]
            .into_iter()
            .map(OsString::from)
            .collect(),
        &mut std::io::empty(),
        false,
        "delete",
    );
    assert_eq!(delete.outcome.stdout, "");
    assert_eq!(
        delete.outcome.stderr,
        "provider credential backend is unsupported\n"
    );
    assert_eq!(delete.outcome.exit_code, 4);
    assert_eq!(delete.resolver_calls, 0);

    let set = credential_test_support::run(
        [
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--stdin",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        &mut b"stdin-secret".as_slice(),
        false,
        "set",
    );
    assert_eq!(set.outcome.stdout, "");
    assert_eq!(
        set.outcome.stderr,
        "provider credential backend is unsupported\n"
    );
    assert_eq!(set.outcome.exit_code, 4);
    assert_eq!(set.resolver_calls, 0);
    subprocess_scenarios();
}

fn subprocess_scenarios() {
    for case in CHILD_CASES {
        let output = spawn_child(case.scenario, case.command, case.input, case.terminal);
        assert_eq!(
            output.status.code(),
            Some(case.expected_code),
            "{}",
            case.scenario
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            case.expected_stdout,
            "{}",
            case.scenario
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("process-secret-marker"),
            "{}",
            case.scenario
        );
        assert!(!stderr.contains("backend-detail"), "{}", case.scenario);
        assert_eq!(
            stderr,
            expected_stderr(case.scenario, case.expected_code),
            "{}",
            case.scenario
        );
    }
}

fn expected_stderr(scenario: &str, code: i32) -> &'static str {
    match (scenario, code) {
        (_, 0) => "",
        (
            "set" | "delete" | "exact4096" | "tty" | "set-resolver-error" | "set-backend-error",
            _,
        ) => "provider credential backend is unsupported\n",
        _ => "provider credential operation failed\n",
    }
}

fn spawn_child(
    scenario: &str,
    command: &[&str],
    input: &[u8],
    _terminal: bool,
) -> std::process::Output {
    let mut child = Command::new(std::env::current_exe().expect("harness executable"))
        .arg("--child")
        .arg(scenario)
        .args(command)
        .env("OPENAI_API_KEY", "process-secret-marker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start harness child");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");
    child.wait_with_output().expect("wait harness child")
}

fn run_child(mut arguments: Vec<OsString>) -> ! {
    let scenario = arguments.remove(0).into_string().expect("scenario");
    let terminal = scenario == "tty";
    let result =
        credential_test_support::run(arguments, &mut std::io::stdin(), terminal, &scenario);
    write_process_outcome(&result.outcome)
}

fn write_process_outcome(outcome: &ProcessOutcome) -> ! {
    let _ = std::io::stdout().write_all(outcome.stdout.as_bytes());
    let _ = std::io::stderr().write_all(outcome.stderr.as_bytes());
    std::process::exit(outcome.exit_code);
}
