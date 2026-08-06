//! GOCODE Runtime Daemon — library crate.
//!
//! Exports the public API for the daemon process:
//! configuration, error types, and future subsystems.

pub mod application;
pub mod bootstrap;
pub mod canonical_provider;
mod canonical_provider_factory;
mod client_profile;
pub mod config;
pub mod error;
pub mod host;
pub mod launch_identity;
pub mod lock;
pub mod operational_telemetry;
pub mod protected_activation;
pub mod provider_activation;
pub mod recovery;
pub mod replay_key;
pub mod shutdown;
