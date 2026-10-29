//! Per-invocation macOS Seatbelt helper.
//!
//! The runtime writes one sandbox profile to an inherited descriptor, spawns
//! this binary, and the helper applies that profile to itself before replacing
//! itself with the requested program. The helper never interprets a shell
//! command and never widens the profile it receives.

#![allow(unsafe_code)]

#[cfg(target_os = "macos")]
mod args;
#[cfg(target_os = "macos")]
mod exec;
#[cfg(target_os = "macos")]
mod profile;
#[cfg(target_os = "macos")]
mod seatbelt;
#[cfg(target_os = "macos")]
mod self_test;

use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    self_test::run_or_launch()
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    // The helper is macOS-only. Other platforms build a stub so the workspace
    // still compiles there, but the binary never executes a command.
    eprintln!("runne-sandbox-helper: macOS-only binary");
    ExitCode::from(1)
}
