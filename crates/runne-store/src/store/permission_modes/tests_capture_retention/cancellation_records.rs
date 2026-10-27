use super::{
    attempt::Attempt,
    metadata::Area,
    observations::Spent,
    paths,
    receipts::{Occupation, Stop},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(super) fn absent(root: &Path, area: &Area) {
    area.daemon(root);
    let workspace = root.join(&area.nested).join("workspace");
    paths::directory(&workspace);
    for name in ["effect-marker", "proceed"] {
        let error = std::fs::symlink_metadata(workspace.join(name)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Exit {
    Exited { code: u8 },
    Signaled { signal: i32, core_dumped: bool },
}
impl From<runne_platform::local_command_linux::LinuxLeaderExitKindV1> for Exit {
    fn from(value: runne_platform::local_command_linux::LinuxLeaderExitKindV1) -> Self {
        use runne_platform::local_command_linux::LinuxLeaderExitKindV1 as E;
        match value {
            E::Exited { code } => Self::Exited { code },
            E::Signaled {
                signal,
                core_dumped,
            } => Self::Signaled {
                signal,
                core_dumped,
            },
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cut {
    pub version: u8,
    pub role: String,
    pub original: Area,
    pub exit: Exit,
    pub released: bool,
    pub reaped: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_eof: bool,
    pub stderr_eof: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub terminal_empty: bool,
    pub fresh_empty: bool,
    pub spent: Spent,
    pub stop: Stop,
    pub occupation: Occupation,
    pub attempt: Attempt,
    pub command: String,
    pub key: String,
    pub expected_version: u64,
    pub outcome: String,
    pub stream_version: u64,
    pub event_ids: Vec<Vec<u8>>,
}
impl Cut {
    pub fn validate(&self, a: &Area) {
        assert_eq!(self.version, 1);
        assert_eq!(self.role, "writer-cut");
        assert_eq!(&self.original, a);
        assert!(self.released && self.reaped && self.stdout_eof && self.stderr_eof);
        assert!(self.terminal_empty && self.fresh_empty);
        assert_eq!(self.stdout, b"ready");
        assert!(self.stderr.is_empty());
        assert_eq!((self.stdout_bytes, self.stderr_bytes), (5, 0));
        match self.exit {
            Exit::Exited { .. } => {}
            Exit::Signaled { signal, .. } => assert!((1..=64).contains(&signal)),
        }
        let command: runne_domain::id::CommandId = self.command.parse().unwrap();
        assert_eq!(command.to_string(), self.command);
        assert_eq!(self.key, format!("g3-cancel-{}", a.context.run));
        assert_eq!(self.outcome, "TaskRunCancellationRequested");
        assert_eq!(self.stream_version, self.expected_version + 1);
        assert!(!self.event_ids.is_empty());
        for id in &self.event_ids {
            assert_eq!(id.len(), 16);
        }
        assert_eq!(self.event_ids.len() as u64, self.stream_version);
        self.spent.assert_original(a);
        super::receipts::validate_stop(
            &self.stop,
            a,
            self.event_ids.last().unwrap(),
            self.stream_version,
        );
        super::receipts::validate_occupation(&self.occupation, a, None);
        self.attempt.validate(a, "running");
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResultRecord {
    pub version: u8,
    pub role: String,
    pub cut: Cut,
    pub recovery_pid: u32,
    pub removed: bool,
}
