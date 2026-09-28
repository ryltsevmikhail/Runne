//! Read-only DP1 readiness projection for `runned doctor` (D1.5, 2026-09-28).
//!
//! Reads the runtime database through one read-only connection and reports
//! bounded, closed checks. No repair, no login, no retry: doctor never
//! mutates state. An absent database is `warn` (fresh install), a broken one
//! is `fail`; readiness never changes `execution_ready` — the exit code stays
//! owned by the config/provider checks.

use crate::doctor::DoctorCheck;

const READ_ONLY: rusqlite::OpenFlags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;

/// The runtime database path, mirroring the built-in defaults layout.
fn runtime_db_path() -> std::path::PathBuf {
    crate::config::resolve_runtime_dir()
        .join("runne-daemon")
        .join("event-log.db")
}

/// Collects the readiness checks for the runtime database.
#[must_use]
pub fn collect() -> Vec<DoctorCheck> {
    let path = runtime_db_path();
    let mut checks = vec![db_integrity(&path), terminal_outbox(&path)];
    checks.push(uncertain_attempts(&path));
    // Build-capability facts of the DP1 composition: the text-only path is
    // supported, and the project-controlled channels stay unavailable until
    // their activation gates exist.
    checks.push(DoctorCheck {
        id: "readiness.text_only_path",
        status: "pass",
    });
    checks.push(DoctorCheck {
        id: "readiness.tools_disabled",
        status: "pass",
    });
    checks
}

fn db_integrity(path: &std::path::Path) -> DoctorCheck {
    let Ok(connection) = rusqlite::Connection::open_with_flags(path, READ_ONLY) else {
        return DoctorCheck {
            id: "readiness.db_integrity",
            status: "warn",
        };
    };
    let quick: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .unwrap_or_else(|_| "unreadable".to_owned());
    DoctorCheck {
        id: "readiness.db_integrity",
        status: if quick == "ok" { "pass" } else { "fail" },
    }
}

fn scalar_count(path: &std::path::Path, sql: &str) -> Option<i64> {
    let connection = rusqlite::Connection::open_with_flags(path, READ_ONLY).ok()?;
    connection.query_row(sql, [], |row| row.get(0)).ok()
}

fn terminal_outbox(path: &std::path::Path) -> DoctorCheck {
    let pending = scalar_count(
        path,
        "SELECT COUNT(*) FROM provider_terminal_outbox WHERE state != 2 OR applied_at IS NULL",
    );
    DoctorCheck {
        id: "readiness.terminal_outbox",
        status: match pending {
            None => "warn",
            Some(0) => "pass",
            Some(_) => "warn",
        },
    }
}

fn uncertain_attempts(path: &std::path::Path) -> DoctorCheck {
    let uncertain = scalar_count(
        path,
        "SELECT COUNT(*) FROM provider_dispatch_attempts WHERE state = 6",
    );
    DoctorCheck {
        id: "readiness.uncertain_attempts",
        status: match uncertain {
            None => "warn",
            Some(0) => "pass",
            Some(_) => "warn",
        },
    }
}
