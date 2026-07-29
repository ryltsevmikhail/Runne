//! Recovery task enumeration.
//!
//! After bootstrap, the daemon inspects the Event Log for in-flight
//! `TaskRun` instances and returns a recovery state that guides the
//! startup/shutdown behaviour.
//!
//! The recovery module uses the `events` table as a proxy to detect
//! whether the database contains any committed event data that may
//! have been in-flight when the previous daemon instance terminated.

use crate::error::DaemonError;
use rusqlite::Connection;

/// Recovery state after bootstrapping the Event Log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// All `TaskRun` instances are terminal or pending — ready to
    /// proceed with normal startup.
    Ready,
    /// At least one non-terminal `TaskRun` was detected — the
    /// daemon should initiate recovery before accepting new work.
    RecoveryBlocked,
    /// Database corruption or integrity violation detected —
    /// requires manual intervention.
    IntegrityBlocked,
}

/// Enumerate recovery tasks by probing the `events` table.
///
/// In a production implementation this would inspect the
/// `task_run_streams` / `aggregate_streams` tables and correlate
/// with in-flight events.  For the Phase 4 bootstrap milestone we
/// use a simplified proxy: if any rows exist in `events`, the
/// database is considered to have residual data and recovery is
/// signalled.
///
/// - Empty DB → `Ready`
/// - DB with events → `RecoveryBlocked`
/// - Query failure → `IntegrityBlocked` (wrapped in `Bootstrap` error)
pub fn enumerate_recovery_tasks(conn: &Connection) -> Result<RecoveryState, DaemonError> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .map_err(|e| DaemonError::Bootstrap(format!("recovery enumeration query failed: {e}")))?;

    if count > 0 {
        Ok(RecoveryState::RecoveryBlocked)
    } else {
        Ok(RecoveryState::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gocode_store::schema;

    #[test]
    fn empty_db_returns_ready() {
        let conn = schema::open_with_pragmas(":memory:").unwrap();
        schema::apply_migrations(&conn).unwrap();
        let state = enumerate_recovery_tasks(&conn).unwrap();
        assert_eq!(state, RecoveryState::Ready);
    }
}
