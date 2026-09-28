//! Fixture support for the headless `exec` CLI tests: reuses the live-daemon
//! harness from the read-only `task` tests and adds a stdin-capable CLI
//! runner for the non-TTY prompt contract.

#![cfg(unix)]

#[allow(dead_code)]
#[path = "../task_cli_parts/support.rs"]
pub mod task_support;

pub use task_support::{
    connect_client, exit_code, parse_json_error_envelope, run_cli, seed_conversation,
    start_test_daemon, stop_daemon,
};

use std::process::{Command, Stdio};

/// Runs the real CLI binary with piped stdin (the headless non-TTY path).
pub async fn run_cli_with_stdin(arguments: &[&str], stdin: &str) -> std::process::Output {
    let executable = env!("CARGO_BIN_EXE_runne");
    let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
    let stdin = stdin.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(executable)
            .args(&arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn CLI");
        if let Some(pipe) = child.stdin.as_mut() {
            use std::io::Write as _;
            pipe.write_all(stdin.as_bytes()).expect("write stdin");
        }
        drop(child.stdin.take());
        child.wait_with_output().expect("run CLI")
    })
    .await
    .expect("join CLI")
}

/// Parses every stdout line as JSON and returns them in order.
pub fn parse_jsonl_lines(output: &std::process::Output, context: &str) -> Vec<serde_json::Value> {
    let stdout = String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout");
    stdout
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("{context}: line {line:?}: {error}"))
        })
        .collect()
}
