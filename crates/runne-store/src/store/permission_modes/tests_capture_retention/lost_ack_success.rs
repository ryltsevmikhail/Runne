//! Guest-only owner crash after independently observed native terminal commit.
use super::super::{fixture, lost_ack_request::Request, success_recovery};
use super::logical_reader;
use crate::schema::{self, ConnectionMode, ManagedConnection};
use runne_application::commands::CommandOutcome;
use runne_domain::id::{EventLogLineageId, TaskRunId};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[path = "lost_ack_success_claim.rs"]
mod claim;
#[path = "lost_ack_success_controller.rs"]
mod controller;
#[path = "lost_ack_success_facts.rs"]
mod facts;
#[path = "lost_ack_success_recovery.rs"]
mod recovery;
#[path = "lost_ack_success_trust.rs"]
mod trust;
#[path = "lost_ack_success_writer.rs"]
mod writer;
const ROLE: &str = "RUNNE_LOSTACK_SUCCESS_ROLE";
const ROOT: &str = "RUNNE_LOSTACK_SUCCESS_ROOT";
const SELECTOR: &str = "store::permission_modes::tests_capture_retention::lost_ack::success_history::committed_native_effect_owner_crash_recovers_without_redispatch";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    path: PathBuf,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    run: [u8; 16],
    controller: u32,
    cgroup: String,
    mount: PathBuf,
}
impl Context {
    fn database(&self) -> fixture::ExistingDatabase<'_> {
        fixture::ExistingDatabase {
            path: &self.path,
            authority: self.authority,
            lineage: self.lineage,
        }
    }
    fn check(&self) {
        assert_ne!(self.controller, 0);
        assert_eq!(
            self.cgroup,
            std::fs::read_to_string("/proc/self/cgroup").unwrap()
        );
        assert_eq!(self.mount, std::fs::read_link("/proc/self/ns/mnt").unwrap());
    }
    fn reader(&self) -> ManagedConnection {
        schema::reopen_managed_connection_validated(&self.path, ConnectionMode::Reader, |c| {
            if schema::read_authority_id(c)? != Some(self.authority)
                || schema::read_event_log_lineage_id(c)? != Some(self.lineage)
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(())
        })
        .unwrap()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    original_facts: Vec<u8>,
    trust: trust::OriginalTrust,
    request: Vec<u8>,
    command: [u8; 16],
    task: [u8; 16],
    attempt: [u8; 16],
    fingerprint: [u8; 32],
    key: String,
    version: u64,
    area: Vec<u8>,
    workspace: PathBuf,
    writer: u32,
}
impl Intent {
    fn expected(&self) -> CommandOutcome {
        CommandOutcome::TaskRunCompleted {
            taskrun_id: TaskRunId::from_bytes(self.task),
            new_version: self.version,
        }
    }
}

fn write(root: &Path, name: &str, value: &impl Serialize) {
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(bytes.len() <= 65_536);
    assert!(!root.join(name).exists());
    let staged = root.join(format!("{name}.part"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    std::fs::rename(staged, root.join(name)).unwrap();
}
fn read<T: serde::de::DeserializeOwned>(root: &Path, name: &str) -> T {
    let bytes = std::fs::read(root.join(name)).unwrap();
    assert!(bytes.len() <= 65_536);
    serde_json::from_slice(&bytes).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}
fn pause(until: Instant) {
    assert!(Instant::now() < until, "bounded lost-ACK role wait");
    std::thread::sleep(Duration::from_millis(5));
}
struct Owned(Option<Child>);
impl Owned {
    fn spawn(root: &Path, role: &str) -> Self {
        Self(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", SELECTOR, "--nocapture", "--test-threads=1"])
                .env(ROLE, role)
                .env(ROOT, root)
                .stdin(Stdio::null())
                // The original caller never receives a terminal response from W.
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        ))
    }
    fn wait(&mut self, until: Instant) -> std::process::ExitStatus {
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                self.0.take();
                return status;
            }
            pause(until);
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn committed_native_effect_owner_crash_recovers_without_redispatch() {
    if let Some(role) = std::env::var_os(ROLE) {
        let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
        let context: Context = read(&root, "context.json");
        context.check();
        assert_ne!(context.controller, std::process::id());
        match role.to_str().unwrap() {
            "writer" => writer::run(&root, &context),
            "recovery" => recovery::run(&root, &context, false),
            "conflict" => recovery::run(&root, &context, true),
            _ => panic!("unknown lost-ACK role"),
        }
        return;
    }
    assert!(std::env::var_os(ROOT).is_none());
    controller::supervise();
}
