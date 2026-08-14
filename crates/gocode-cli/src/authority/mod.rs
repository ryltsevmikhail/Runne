//! Transport-only authority command parsing and immutable Git subject capture.

mod adapter;
mod command;
mod git;
mod lifecycle;
#[cfg(any(test, target_os = "macos"))]
mod review;
mod tty;

use std::collections::VecDeque;
use std::ffi::OsString;

use super::CliError;

pub fn run(arguments: VecDeque<OsString>) -> Result<String, CliError> {
    command::run(arguments)
}
