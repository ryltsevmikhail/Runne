#![allow(dead_code)]
#![allow(clippy::too_many_lines)]

#[path = "../src/main.rs"]
mod cli;

use std::ffi::OsString;
use std::io::Write as _;
use std::process::{Command, Stdio};

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--child")) {
        run_child(arguments.collect());
    }

    let delete = cli::credential_test_support::run(
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

    let set = cli::credential_test_support::run(
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
        let failed_set = cli::credential_test_support::run(
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

    for (scenario, command, input, terminal, expected_stdout, expected_code) in [
        (
            "set",
            vec![
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--stdin",
            ],
            b"stdin-secret".as_slice(),
            false,
            "configured\n",
            0,
        ),
        (
            "status",
            vec!["provider", "credential", "status", "--provider", "openai"],
            b"".as_slice(),
            false,
            "configured\n",
            0,
        ),
        (
            "delete",
            vec!["provider", "credential", "delete", "--provider", "openai"],
            b"".as_slice(),
            false,
            "missing\n",
            0,
        ),
        (
            "exact4096",
            vec![
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--stdin",
            ],
            &vec![b'x'; 4_096],
            false,
            "configured\n",
            0,
        ),
        (
            "tty",
            vec![
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--stdin",
            ],
            b"credential".as_slice(),
            true,
            "",
            1,
        ),
        (
            "backend-error",
            vec!["provider", "credential", "status", "--provider", "openai"],
            b"".as_slice(),
            false,
            "",
            1,
        ),
        (
            "set-resolver-error",
            vec![
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--stdin",
            ],
            b"stdin-secret".as_slice(),
            false,
            "",
            1,
        ),
        (
            "set-backend-error",
            vec![
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--stdin",
            ],
            b"stdin-secret".as_slice(),
            false,
            "",
            1,
        ),
        (
            "missing-stdin",
            vec!["provider", "credential", "set", "--provider", "openai"],
            b"".as_slice(),
            false,
            "",
            2,
        ),
    ] {
        let output = spawn_child(scenario, &command, input, terminal);
        assert_eq!(output.status.code(), Some(expected_code), "{scenario}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            expected_stdout,
            "{scenario}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("process-secret-marker"), "{scenario}");
        assert!(!stderr.contains("backend-detail"), "{scenario}");
        assert_eq!(
            stderr,
            expected_stderr(scenario, expected_code),
            "{scenario}"
        );
    }
}

fn expected_stderr(scenario: &str, code: i32) -> &'static str {
    match (scenario, code) {
        (_, 0) => "",
        ("tty", _) => "provider credential input is invalid\n",
        ("missing-stdin", _) => {
            "Usage:\n  gocode [--profile PATH] conversation create [--workspace-id UUID]\n  gocode [--profile PATH] conversation send --conversation-id UUID --expected-version N --text TEXT\n  gocode [--profile PATH] conversation messages --conversation-id UUID\n"
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
        cli::credential_test_support::run(arguments, &mut std::io::stdin(), terminal, &scenario);
    cli::write_process_outcome(&result.outcome)
}
