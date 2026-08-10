//! Integration tests for CLI foundation: help, version, output format, exit codes.

#![cfg(unix)]

use std::process::Command;

fn run_cli(arguments: &[&str]) -> std::process::Output {
    let executable = env!("CARGO_BIN_EXE_gocode");
    Command::new(executable)
        .args(arguments)
        .output()
        .expect("run CLI")
}

include!("cli_foundation/help.rs");
include!("cli_foundation/format_and_exit.rs");
include!("cli_foundation/diagnostics.rs");
include!("cli_foundation/completion.rs");
