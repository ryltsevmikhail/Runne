use super::{metadata::Area, observations::one};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub task: Vec<u8>,
    pub conversation: Vec<u8>,
    pub workspace: Vec<u8>,
    pub attempt: Vec<u8>,
    pub node: Vec<u8>,
    pub epoch: i64,
    pub fence: i64,
    pub digest: Vec<u8>,
    pub executable: Option<Vec<u8>>,
    pub workspace_version: Option<i64>,
    pub root_version: Option<i64>,
    pub root: Option<Vec<u8>>,
    pub trust_epoch: Option<i64>,
    pub trust_revision: Option<i64>,
    pub source_policy: Option<i64>,
    pub command_policy: Option<i64>,
    pub approval: Option<Vec<u8>>,
    pub area: Vec<u8>,
    pub state: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: Option<i32>,
    pub updated: i64,
}
impl Attempt {
    pub fn validate(&self, a: &Area, state: &str) {
        let id = a.identity();
        assert_eq!(self.task, id.taskrun_id.as_bytes());
        assert_eq!(self.attempt, id.attempt_id.as_bytes());
        assert_eq!(self.node, a.authority);
        assert_eq!(self.epoch, i64::try_from(a.epoch).unwrap());
        assert_eq!(self.fence, i64::try_from(id.fence.0).unwrap());
        let workspace: runne_domain::id::WorkspaceId = a.workspace.parse().unwrap();
        assert_eq!(self.workspace, workspace.as_bytes());
        assert_eq!(self.conversation.len(), 16);
        assert_eq!(self.digest, a.command_digest);
        assert_eq!(self.area, a.area);
        assert_eq!(self.state, state);
        assert_eq!(self.exit, None);
        assert!(self.stdout.is_empty() && self.stderr.is_empty());
        assert!(self.updated >= 0);
    }
    pub fn same_immutable(&self, old: &Self) {
        let mut expected = old.clone();
        expected.state = self.state.clone();
        expected.updated = self.updated;
        assert_eq!(self, &expected);
        assert!(self.updated >= old.updated);
    }
}
pub(super) fn observe(c: &Connection, a: &Area, state: &str) -> Attempt {
    let value=one(c,"SELECT taskrun_id,conversation_id,workspace_id,attempt_id,node_id,node_epoch,
        fence,command_digest,executable_digest,workspace_version,admitted_root_version,
        admitted_root_identity,trust_epoch,trust_revision,source_policy_version,command_policy_version,
        approval_id,managed_area_identity,state,stdout,stderr,exit_code,updated_at
        FROM taskrun_local_command_attempts WHERE taskrun_id=?1",a,|r| Ok(Attempt {
        task:r.get(0)?,conversation:r.get(1)?,workspace:r.get(2)?,attempt:r.get(3)?,node:r.get(4)?,
        epoch:r.get(5)?,fence:r.get(6)?,digest:r.get(7)?,executable:r.get(8)?,workspace_version:r.get(9)?,
        root_version:r.get(10)?,root:r.get(11)?,trust_epoch:r.get(12)?,trust_revision:r.get(13)?,
        source_policy:r.get(14)?,command_policy:r.get(15)?,approval:r.get(16)?,area:r.get(17)?,
        state:r.get(18)?,stdout:r.get(19)?,stderr:r.get(20)?,exit:r.get(21)?,updated:r.get(22)?,
    }));
    value.validate(a, state);
    value
}
