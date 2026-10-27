//! Prefix-preserving cumulative output and actual live/EOF oracles.
use super::fixture::Fixture;
use crate::store::LocalCommandPermissionTerminalOutputV1;
use runne_application::permission_modes::LocalCommandPermissionBindingV1;
use runne_platform::{
    local_command_linux::PermissionChildV1,
    process_managed_area::LinuxManagedArea,
};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_eof: bool,
    stderr_eof: bool,
}
impl Output {
    fn poll(&mut self, child: &mut PermissionChildV1<'_>) {
        child.poll_output().unwrap();
        let c = child.take_output();
        assert!(!c.stdout_truncated && !c.stderr_truncated && !c.observed_bytes_overflowed);
        assert!(self.stdout.len() + c.stdout.len() <= 5);
        assert!(self.stderr.len() + c.stderr.len() == 0);
        self.stdout.extend(c.stdout);
        self.stderr.extend(c.stderr);
        assert_eq!(c.stdout_observed_bytes, self.stdout.len() as u64);
        assert_eq!(c.stderr_observed_bytes, self.stderr.len() as u64);
        assert!(!self.stdout_eof || c.stdout_eof);
        assert!(!self.stderr_eof || c.stderr_eof);
        self.stdout_eof = c.stdout_eof;
        self.stderr_eof = c.stderr_eof;
    }
    pub(super) fn ready(child: &mut PermissionChildV1<'_>) -> Self {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut output = Self::default();
        loop {
            output.poll(child);
            assert!(!output.stdout_eof && !output.stderr_eof);
            assert_eq!(child.try_wait().unwrap(), None);
            if output.stdout == b"ready" { return output; }
            assert!(Instant::now() < deadline, "bounded ready prefix wait");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub(super) fn assert_live(&mut self, child: &mut PermissionChildV1<'_>, area: &LinuxManagedArea) {
        self.poll(child);
        assert_eq!(self.stdout, b"ready");
        assert!(!self.stdout_eof && !self.stderr_eof);
        assert_eq!(child.try_wait().unwrap(), None);
        assert!(area.is_populated().unwrap());
        assert!(area.prove_empty().is_err());
        assert!(child.terminal_evidence().is_err());
    }
    pub(super) fn drain(&mut self, child: &mut PermissionChildV1<'_>) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            self.poll(child);
            if self.stdout_eof && self.stderr_eof { break; }
            assert!(Instant::now() < deadline, "bounded actual both EOF");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(self.stdout, b"ready");
        assert!(self.stderr.is_empty());
    }
    pub(super) fn forged_eof(&self) -> LocalCommandPermissionTerminalOutputV1 {
        assert!(!self.stdout_eof && !self.stderr_eof);
        self.build()
    }
    pub(super) fn real_eof(&self) -> LocalCommandPermissionTerminalOutputV1 {
        assert!(self.stdout_eof && self.stderr_eof);
        self.build()
    }
    fn build(&self) -> LocalCommandPermissionTerminalOutputV1 {
        LocalCommandPermissionTerminalOutputV1::new(
            self.stdout.clone(), self.stderr.clone(),
            self.stdout.len() as u64, self.stderr.len() as u64,
            false, false, true, true, false,
        ).unwrap()
    }
}

pub(super) fn assert_running(f: &Fixture, b: &LocalCommandPermissionBindingV1) {
    let reader = f.store.inner.reader.lock().unwrap();
    let id = b.assignment().taskrun_id;
    for (table, state) in [
        ("taskrun_local_command_attempts", "running"),
        ("taskrun_assignment_occupations", "active"),
    ] {
        let actual: String = reader.query_row(
            &format!("SELECT state FROM {table} WHERE taskrun_id=?1"),
            [id.as_bytes()], |r| r.get(0),
        ).unwrap();
        assert_eq!(actual, state);
    }
    for table in ["x2_permission_terminal", "taskrun_terminal_settlement_receipts"] {
        let count: i64 = reader.query_row(
            &format!("SELECT count(*) FROM {table} WHERE taskrun_id=?1"),
            [id.as_bytes()], |r| r.get(0),
        ).unwrap();
        assert_eq!(count, 0);
    }
    let spent: i64 = reader.query_row(
        "SELECT count(*) FROM x2_permission_spent WHERE taskrun_id=?1",
        [id.as_bytes()], |r| r.get(0),
    ).unwrap();
    assert_eq!(spent, 1);
}
