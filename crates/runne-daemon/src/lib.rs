//! Runne Runtime Daemon — library crate.
//!
//! Exports the public API for the daemon process:
//! configuration, error types, and future subsystems.

pub mod application;
pub mod bootstrap;
pub mod canonical_provider;
mod client_profile;
pub mod config;
pub mod doctor;
pub mod error;
pub mod host;
pub mod launch_identity;
#[cfg(target_os = "linux")]
pub mod linux_cli_credential_host;
pub mod lock;
pub mod operational_telemetry;
pub mod protected_activation;
pub mod provider_activation;
pub mod recovery;
pub mod replay_key;
#[cfg(unix)]
pub mod safe_tool_helper;
pub mod shutdown;
/// Measured image pins for the adopted terminal installation.
#[cfg(unix)]
pub mod terminal_image_policy;

#[cfg(test)]
mod source_boundary_tests;
