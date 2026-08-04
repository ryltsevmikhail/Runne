//! Database schema — DDL, migrations, and startup PRAGMA gates.
//!
//! The schema consists of:
//! - `schema_version` — tracks applied migrations
//! - `event_log_state` — singleton row for global position counter
//! - `aggregate_streams` — per-aggregate stream metadata
//! - `events` — committed event rows
//! - `command_receipts` — idempotency receipt store

use gocode_domain::id::{EventLogLineageId, validate_uuid_v7_bytes};
use rand::RngCore;
use rand::rngs::OsRng;
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Result as SqliteResult};

/// Current schema version. Increment when adding new DDL migrations.
pub const CURRENT_SCHEMA_VERSION: i64 = 11;

/// Fail-closed reason returned before a file-backed database is made writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaOpenDiagnostic {
    ZeroByteDatabase,
    SidecarPresent,
    FileIdentityUncertain,
    UnsafePath,
}

impl fmt::Display for SchemaOpenDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroByteDatabase => "ZeroByteDatabase",
            Self::SidecarPresent => "SidecarPresent",
            Self::FileIdentityUncertain => "FileIdentityUncertain",
            Self::UnsafePath => "UnsafePath",
        })
    }
}

impl std::error::Error for SchemaOpenDiagnostic {}

fn diagnostic_error(diagnostic: SchemaOpenDiagnostic) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(diagnostic))
}

include!("schema/admission_identity.rs");
include!("schema/admission_open.rs");
include!("schema/admission_recovery.rs");
include!("schema/admission_classification.rs");
include!("schema/migration_control.rs");
include!("schema/validation.rs");
include!("schema/startup.rs");
include!("schema/migrations/v1_v3.rs");
include!("schema/migrations/v4.rs");
include!("schema/migrations/v5_v6.rs");
include!("schema/migrations/v7_v8.rs");
include!("schema/migrations/v9.rs");
include!("schema/migrations/v10_v11.rs");
include!("schema/open.rs");
include!("schema/authority_identity.rs");
include!("schema/authority_launch.rs");
include!("schema/replay.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    const TEST_ID: [u8; 16] = [0x42; 16];

    fn initialize_v1(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
    }

    include!("schema/tests/admission.rs");
    include!("schema/tests/migrations.rs");
    include!("schema/tests/released.rs");
    include!("schema/tests/recovery_compatibility.rs");
}
