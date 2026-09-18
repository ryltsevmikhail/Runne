//! D1.3 typed SQLite/WAL recovery diagnosis.
//!
//! [`diagnose_managed_recovery`] classifies the recovery state of one
//! file-backed managed database without repairing or writing anything. It is a
//! read-only diagnostic counterpart of the fail-closed admission and startup
//! gates in [`super`]:
//!
//! 1. Pre-open classification replicates the `admission_open` preflight states
//!    that precede any connection attempt (see
//!    `open_classified_immutable_read_only`): unsafe path, uncertain file
//!    identity, zero-byte main database.
//! 2. Reader admission runs through `open_managed_connection` with
//!    [`super::ConnectionMode::Reader`]. Present `-wal`/`-shm` sidecars are
//!    NOT rejected up front: the factory routes them through the same
//!    owner-private hot-reader admission a production restart uses, so a
//!    normally closed store (whose reader closes last and cannot remove the
//!    checkpointed WAL) still diagnoses as
//!    [`StoreRecoveryDiagnosis::Ready`]. Any [`super::SchemaOpenDiagnostic`]
//!    payload carried by a failure is mapped to its typed variant, which is
//!    how an inadmissible sidecar layout surfaces as
//!    [`StoreRecoveryDiagnosis::SidecarPresent`] or
//!    [`StoreRecoveryDiagnosis::FileIdentityUncertain`].
//! 3. After a successful open the startup gates of `startup.rs` run
//!    individually so each failure keeps its own variant:
//!    `PRAGMA integrity_check`, the durable `schema_version` table versus
//!    [`super::CURRENT_SCHEMA_VERSION`] (managed stores keep
//!    `PRAGMA user_version` at 0; it is only an upper bound during
//!    classification), then `PRAGMA foreign_key_check`, the managed PRAGMA
//!    profile, and replay-snapshot binding.
//!
//! Reader-mode diagnosis never initializes WAL; a writer open performs
//! `initialize_wal_once`, so recovery of a database whose checkpointed WAL
//! sidecars were removed is legal and still diagnoses as
//! [`StoreRecoveryDiagnosis::Ready`]. The read-only open does let SQLite
//! materialize an empty `-wal` and the `-shm` index every WAL read needs;
//! no frames are ever written.

use std::path::Path;

use rusqlite::Connection;

use super::{
    CURRENT_SCHEMA_VERSION, ConnectionMode, SchemaOpenDiagnostic, open_managed_connection,
    path_is_safe,
};

/// Typed, mutually exclusive recovery disposition of one store file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreRecoveryDiagnosis {
    /// The database passed every admission and startup gate unchanged.
    Ready,
    /// The main database file is zero bytes long.
    ZeroByteDatabase,
    /// The sidecar set cannot be admitted fail-closed.
    SidecarPresent,
    /// The main file identity cannot be proven (missing, symlink, swapped).
    FileIdentityUncertain,
    /// The requested path cannot be addressed safely.
    UnsafePath,
    /// `PRAGMA integrity_check` reported corruption.
    IntegrityCheckFailed,
    /// The durable `schema_version` table differs from the current schema
    /// version, i.e. an older (or newer, classified) release wrote this file.
    SchemaVersionMismatch {
        /// Schema version found in the `schema_version` table.
        found: u32,
        /// [`CURRENT_SCHEMA_VERSION`] expected by this build.
        expected: u32,
    },
    /// The database structure or managed profile failed a startup gate.
    StartupProfileRejected,
    /// The database could not be opened or read at all.
    Unavailable,
}

/// Classifies the recovery state of `path` without mutating it.
///
/// The function opens the database read-only through the same managed
/// connection factory used at startup, so a `Ready` verdict means the file
/// would also pass the managed admission and startup gates of a restart.
#[must_use]
pub fn diagnose_managed_recovery(path: &Path) -> StoreRecoveryDiagnosis {
    if !path_is_safe(path) {
        return StoreRecoveryDiagnosis::UnsafePath;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_symlink() => {}
        _ => return StoreRecoveryDiagnosis::FileIdentityUncertain,
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() > 0 => {}
        Ok(_) => return StoreRecoveryDiagnosis::ZeroByteDatabase,
        Err(_) => return StoreRecoveryDiagnosis::FileIdentityUncertain,
    }
    let connection = match open_managed_connection(path, ConnectionMode::Reader) {
        Ok(connection) => connection,
        Err(error) => return map_open_error(error),
    };
    run_startup_gate_probes(&connection)
}

fn map_open_error(error: rusqlite::Error) -> StoreRecoveryDiagnosis {
    if let rusqlite::Error::ToSqlConversionFailure(payload) = &error
        && let Some(diagnostic) = payload.downcast_ref::<SchemaOpenDiagnostic>()
    {
        return match diagnostic {
            SchemaOpenDiagnostic::ZeroByteDatabase => StoreRecoveryDiagnosis::ZeroByteDatabase,
            SchemaOpenDiagnostic::SidecarPresent => StoreRecoveryDiagnosis::SidecarPresent,
            SchemaOpenDiagnostic::FileIdentityUncertain => {
                StoreRecoveryDiagnosis::FileIdentityUncertain
            }
            SchemaOpenDiagnostic::UnsafePath => StoreRecoveryDiagnosis::UnsafePath,
        };
    }
    StoreRecoveryDiagnosis::Unavailable
}

/// Runs the startup gates of `schema/startup.rs` individually so each failure
/// keeps its own typed variant instead of the gates' shared opaque error.
fn run_startup_gate_probes(connection: &Connection) -> StoreRecoveryDiagnosis {
    let integrity: String =
        match connection.query_row("PRAGMA integrity_check", [], |row| row.get(0)) {
            Ok(integrity) => integrity,
            Err(_) => return StoreRecoveryDiagnosis::Unavailable,
        };
    if integrity != "ok" {
        return StoreRecoveryDiagnosis::IntegrityCheckFailed;
    }
    let schema_version: i64 = match connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    ) {
        Ok(schema_version) => schema_version,
        Err(_) => return StoreRecoveryDiagnosis::Unavailable,
    };
    if schema_version != CURRENT_SCHEMA_VERSION {
        return StoreRecoveryDiagnosis::SchemaVersionMismatch {
            found: u32::try_from(schema_version).unwrap_or(u32::MAX),
            expected: u32::try_from(CURRENT_SCHEMA_VERSION).unwrap_or(u32::MAX),
        };
    }
    if let Ok(mut foreign_key_check) = connection.prepare("PRAGMA foreign_key_check") {
        match foreign_key_check.exists([]) {
            Ok(true) => return StoreRecoveryDiagnosis::StartupProfileRejected,
            Ok(false) => {}
            Err(_) => return StoreRecoveryDiagnosis::Unavailable,
        }
    } else {
        return StoreRecoveryDiagnosis::Unavailable;
    }
    for pragma_profile in [
        ("journal_mode", "wal"),
        ("synchronous", "2"),
        ("foreign_keys", "1"),
    ] {
        let (pragma, expected) = pragma_profile;
        match super::verify_pragma(connection, pragma, expected) {
            Ok(()) => {}
            Err(_) => return StoreRecoveryDiagnosis::StartupProfileRejected,
        }
    }
    #[cfg(target_os = "macos")]
    if super::verify_pragma(connection, "fullfsync", "1").is_err() {
        return StoreRecoveryDiagnosis::StartupProfileRejected;
    }
    if crate::store::snapshot::validate_all_replay_snapshots(connection).is_err() {
        return StoreRecoveryDiagnosis::StartupProfileRejected;
    }
    StoreRecoveryDiagnosis::Ready
}
