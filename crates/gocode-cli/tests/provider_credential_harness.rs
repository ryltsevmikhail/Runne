use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Write as _;
use std::io::{IsTerminal as _, Read};
use std::process::{Command, Stdio};

use gocode_secure_store::{
    MAX_PROVIDER_CREDENTIAL_BYTES, NativeProviderCredentialStore, ProviderCredentialAccessPolicy,
    ProviderCredentialId, ProviderCredentialMaterial, ProviderCredentialStatus,
    ProviderCredentialStore, SecureStoreError,
};
use zeroize::Zeroize as _;

const USAGE: &str = "\
Usage:
  gocode [--profile PATH] conversation create [--workspace-id UUID]
  gocode [--profile PATH] conversation send --conversation-id UUID --expected-version N --text TEXT
  gocode [--profile PATH] conversation messages --conversation-id UUID
  gocode authority --help
  gocode release --help";
#[path = "provider_credential_support/cases.rs"]
mod provider_credential_cases;
use provider_credential_cases::CHILD_CASES;

struct ProcessOutcome {
    stdout: String,
    stderr: String,
    exit_code: i32,
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

include!("../src/cli/token_parsing.rs");
include!("../src/cli/provider_credential.rs");

#[derive(Debug)]
enum CliError {
    Usage,
    CredentialInput,
    CredentialOperation,
    UnsupportedCredentialBackend,
}

impl CliError {
    const fn exit_code(&self) -> i32 {
        if matches!(self, Self::Usage) { 2 } else { 1 }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Usage => USAGE,
            Self::CredentialInput => "provider credential input is invalid",
            Self::CredentialOperation => "provider credential operation failed",
            Self::UnsupportedCredentialBackend => "provider credential backend is unsupported",
        })
    }
}

#[path = "../src/credential_test_support.rs"]
mod credential_test_support;

fn main() {
    direct_scenarios();
    subprocess_scenarios();
}

fn direct_scenarios() {
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
    assert_eq!(delete.outcome.stdout, "missing\n");
    assert_eq!(delete.outcome.stderr, "");
    assert_eq!(delete.delete_calls, 1);
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
    assert_eq!(set.outcome.stdout, "configured\n");
    assert_eq!(set.store_calls, 1);
    assert!(set.store_received_stdin_secret);

    for (scenario, expected_store_calls) in [("set-resolver-error", 0), ("set-backend-error", 1)] {
        let failed_set = credential_test_support::run(
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
            scenario,
        );
        assert_eq!(failed_set.outcome.stdout, "");
        assert_eq!(
            failed_set.outcome.stderr,
            "provider credential operation failed\n"
        );
        assert_eq!(failed_set.resolver_calls, 1);
        assert_eq!(failed_set.store_calls, expected_store_calls);
    }
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
        ("tty", _) => "provider credential input is invalid\n",
        ("missing-stdin", _) => {
            "Usage:\n  gocode [--profile PATH] conversation create [--workspace-id UUID]\n  gocode [--profile PATH] conversation send --conversation-id UUID --expected-version N --text TEXT\n  gocode [--profile PATH] conversation messages --conversation-id UUID\n  gocode authority --help\n  gocode release --help\n"
        }
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
