//! Daemon-owned HTTP serving boundary.
//!
//! Router composition belongs to the daemon application root. This module
//! owns only listener lifecycle, accepted connections, and orderly ingress
//! shutdown.

include!("host/lifecycle.rs");
include!("host/serve.rs");
include!("host/tests.rs");
