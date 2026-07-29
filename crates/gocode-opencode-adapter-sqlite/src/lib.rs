#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Durable SQLite implementation of the OpenCode session-binding port.

/// Durable binding-store implementation.
pub mod binding_store;
/// Deterministic snapshots for durable binding rows.
pub mod codec;
/// SQLite schema, migration, and connection hardening.
pub mod schema;

pub use binding_store::{BindingClock, SqliteSessionBindingStore, SystemBindingClock};
