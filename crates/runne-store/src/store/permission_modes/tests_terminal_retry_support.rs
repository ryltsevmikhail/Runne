//! Exact real-child output and logical fresh-fixture snapshots; guest-only.
use super::fixture::Fixture;
use crate::store::LocalCommandPermissionTerminalOutputV1;
use runne_platform::local_command_linux::PermissionChildV1;
use std::time::{Duration, Instant};

pub(super) struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_observed: u64,
    stderr_observed: u64,
}

impl Output {
    pub(super) fn drain(child: &mut PermissionChildV1<'_>) -> Self {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            child.poll_output().unwrap();
            let c = child.take_output();
            assert!(!c.stdout_truncated && !c.stderr_truncated && !c.observed_bytes_overflowed);
            assert!(stdout.len() + c.stdout.len() <= 65_536);
            assert!(stderr.len() + c.stderr.len() <= 65_536);
            stdout.extend(c.stdout);
            stderr.extend(c.stderr);
            if c.stdout_eof && c.stderr_eof {
                assert_eq!(c.stdout_observed_bytes, stdout.len() as u64);
                assert_eq!(c.stderr_observed_bytes, stderr.len() as u64);
                return Self {
                    stdout,
                    stderr,
                    stdout_observed: c.stdout_observed_bytes,
                    stderr_observed: c.stderr_observed_bytes,
                };
            }
            assert!(Instant::now() < deadline, "bounded real both-EOF drain");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub(super) fn exact(&self) -> LocalCommandPermissionTerminalOutputV1 {
        assert_eq!(self.stdout, b"retry-out");
        assert_eq!(self.stderr, b"retry-err");
        self.build(self.stdout.clone())
    }

    pub(super) fn altered(&self) -> LocalCommandPermissionTerminalOutputV1 {
        let mut stdout = self.stdout.clone();
        stdout[0] ^= 1;
        self.build(stdout)
    }

    fn build(&self, stdout: Vec<u8>) -> LocalCommandPermissionTerminalOutputV1 {
        LocalCommandPermissionTerminalOutputV1::new(
            stdout,
            self.stderr.clone(),
            self.stdout_observed,
            self.stderr_observed,
            false,
            false,
            true,
            true,
            false,
        )
        .unwrap()
    }
}

// Logical row equality only; never SQLite/WAL byte identity or historical DB access.
pub(super) fn snapshot(f: &Fixture) -> Vec<(String, Vec<String>)> {
    let reader = f.store.inner.reader.lock().unwrap();
    let tables: Vec<String> = reader
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    tables
        .into_iter()
        .map(|name| {
            let sql = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
            let mut statement = reader.prepare(&sql).unwrap();
            let columns = statement.column_count();
            let mut rows: Vec<String> = statement
                .query_map([], |row| {
                    let values = (0..columns)
                        .map(|i| row.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(format!("{values:?}"))
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            rows.sort();
            (name, rows)
        })
        .collect()
}

pub(super) fn assert_single_terminal(
    f: &Fixture,
    taskrun: runne_domain::id::TaskRunId,
    original: &runne_application::ports::CommandCommit,
) {
    let reader = f.store.inner.reader.lock().unwrap();
    for table in [
        "x2_permission_terminal",
        "x2_permission_spent",
        "taskrun_terminal_settlement_receipts",
        "taskrun_local_command_attempts",
        "taskrun_assignment_occupations",
    ] {
        let count: i64 = reader.query_row(
            &format!("SELECT count(*) FROM {table} WHERE taskrun_id=?1"),
            [taskrun.as_bytes()],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(count, 1, "one original task-scoped {table} row");
    }
    let receipts: i64 = reader.query_row(
        "SELECT count(*) FROM command_receipts WHERE command_id=?1",
        [original.command_id.as_bytes()],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(receipts, 1);
    assert_eq!(original.events.len(), 1);
    let events: i64 = reader.query_row(
        "SELECT count(*) FROM events WHERE event_id=?1 AND command_id=?2",
        rusqlite::params![original.events[0].event_id().as_bytes(), original.command_id.as_bytes()],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(events, 1);
    let occupation: String = reader.query_row(
        "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
        [taskrun.as_bytes()],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(occupation, "released");
}
