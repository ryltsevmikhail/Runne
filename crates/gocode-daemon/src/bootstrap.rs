//! Bootstrap subsystem — full daemon startup sequence.
//!
//! Implements ADR-0014 bootstrap sequence:
//! acquire three-layer locks, provision or load the replay-integrity key,
//! open the SQLite database, apply schema migrations, reconcile
//! authority metadata, purge stale replay subscriptions, and
//! detect recovery tasks.
//!
//! ## Lock acquisition order
//!
//! 1. Provisional path lock — before DB open, serialises first-start
//!    and replay-key side effects.
//! 2. File identity lock — after DB verify handle (no-follow open).
//! 3. Authority lock — after reading/generating `_authority` from schema v8 DB.

use crate::config::ConfigurationSnapshot;
use crate::error::DaemonError;
use crate::launch_identity::LaunchIdentity;
use crate::lock::{LockSet, MetadataSnapshot};
use crate::replay_key::{ReplayIntegrityKey, ReplayIntegrityKeyManager};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use gocode_api::PendingFirstActivationV1;
use gocode_domain::id::validate_uuid_v7_bytes;
use gocode_store::schema;
use gocode_store::schema::LaunchAuthorityConsumptionError;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

const SIDECAR_MIGRATION_MARKER_KEY: &str = "local_session_sidecars_v1";

// ── Startup mode ──────────────────────────────────────────────────────

/// Describes how the daemon started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupMode {
    /// First time this Event Log has been initialised.
    FirstStart,
    /// Normal restart — DB and metadata existed.
    Restart,
    /// Restart after a recovery phase (currently informational).
    Recovered,
}

// ── BootstrapOutcome ──────────────────────────────────────────────────

/// The complete set of resources acquired during bootstrap.
///
/// All three locks are held, the database is open and migrated,
/// the replay-integrity key is loaded or provisioned.
pub struct BootstrapOutcome {
    /// All three locks held (path, file, authority).
    pub locks: LockSet,
    /// Open writable SQLite connection with schema applied.
    pub db_conn: rusqlite::Connection,
    /// Authority ID from the `_authority` table.
    pub authority_id: [u8; 16],
    /// Stable UUIDv7 authority for peer-authenticated local sessions.
    pub local_session_authority_id: [u8; 16],
    /// Whether the DB file existed before this bootstrap.
    pub db_existed: bool,
    /// How the daemon started.
    pub startup_mode: StartupMode,
    /// Fresh TLS and bootstrap identity for this daemon launch.
    pub launch_identity: LaunchIdentity,
    /// Durable positive generation allocated for this launch.
    pub launch_generation: u64,
    /// Stable internal replay-integrity key.
    pub replay_integrity_key: ReplayIntegrityKey,
}

impl std::fmt::Debug for BootstrapOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapOutcome")
            .field("locks", &self.locks)
            .field("db_conn", &"<Connection>")
            .field("authority_id", &hex::encode(self.authority_id))
            .field("local_session_authority_id", &"<redacted>")
            .field("db_existed", &self.db_existed)
            .field("startup_mode", &self.startup_mode)
            .field("launch_identity", &"<redacted>")
            .field("launch_generation", &self.launch_generation)
            .field("replay_integrity_key", &"<redacted>")
            .finish()
    }
}

// ── Public API ────────────────────────────────────────────────────────

include!("bootstrap/flow.rs");
include!("bootstrap/sidecars.rs");
include!("bootstrap/locks.rs");

#[cfg(test)]
mod tests {
    include!("bootstrap/tests_basic.rs");
    include!("bootstrap/tests_recovery.rs");
}
