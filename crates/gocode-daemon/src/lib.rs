//! GOCODE Runtime Daemon — library crate.
//!
//! Exports the public API for the daemon process:
//! configuration, error types, and future subsystems.

pub mod application;
pub mod bootstrap;
mod client_profile;
pub mod config;
pub mod error;
pub mod host;
pub mod lock;
pub mod recovery;
pub mod shutdown;
pub mod token;
