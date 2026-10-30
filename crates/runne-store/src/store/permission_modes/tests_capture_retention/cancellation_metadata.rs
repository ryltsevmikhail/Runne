use super::paths;
use crate::store::LocalCommandPermissionCaptureV1;
use runne_application::ports::{ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence};
use runne_application::project_trust::{ProjectTrustRecord, ProjectTrustStatus};
use runne_domain::id::{AttemptId, InvocationId, ProjectId, TaskRunId, WorkspaceId};
use runne_platform::process_managed_area::{ManagedAreaBinding, ManagedAreaIdentity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    pub run: String,
    pub controller_pid: u32,
    pub deadline_ns: u64,
    pub cgroup: String,
    pub mount: String,
}
impl Context {
    pub fn new() -> Self {
        Self {
            run: uuid::Uuid::now_v7().to_string(),
            controller_pid: std::process::id(),
            deadline_ns: super::budget::Deadline::new().0,
            cgroup: cgroup(),
            mount: mount(),
        }
    }
    pub fn inherited() -> Self {
        let value = Self {
            run: std::env::var(super::RUN).unwrap(),
            controller_pid: std::env::var(super::CONTROLLER).unwrap().parse().unwrap(),
            deadline_ns: super::budget::Deadline::inherited().0,
            cgroup: std::env::var(super::CGROUP).unwrap(),
            mount: std::env::var(super::MOUNT).unwrap(),
        };
        value.assert_controller();
        value
    }
    pub fn assert_parent(&self) {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let parent: u32 = status
            .lines()
            .find_map(|s| s.strip_prefix("PPid:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(parent, self.controller_pid);
        assert_ne!(std::process::id(), self.controller_pid);
    }
    pub fn assert_controller(&self) {
        assert!(self.controller_pid > 0);
        super::budget::Deadline(self.deadline_ns).check();
        let id = uuid::Uuid::parse_str(&self.run).unwrap();
        runne_domain::id::validate_uuid_v7_bytes(id.as_bytes()).unwrap();
        assert_eq!(id.to_string(), self.run);
        assert!(!self.cgroup.is_empty() && self.cgroup.len() <= 4096);
        assert!(!self.mount.is_empty() && self.mount.len() <= 128);
        assert_eq!(self.cgroup, cgroup());
        assert_eq!(self.mount, mount());
    }
}
fn cgroup() -> String {
    std::fs::read_to_string("/proc/self/cgroup").unwrap()
}
fn mount() -> String {
    std::fs::read_link("/proc/self/ns/mnt")
        .unwrap()
        .to_str()
        .unwrap()
        .into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capture {
    pub task: String,
    pub attempt: String,
    pub fence: u64,
    pub invocation: String,
    pub canonical_digest: [u8; 32],
    pub binding_digest: [u8; 32],
    pub binding: Vec<u8>,
    pub owner: [u8; 16],
    pub generation: u64,
}
impl Capture {
    pub fn of(c: &LocalCommandPermissionCaptureV1) -> Self {
        Self {
            task: c.taskrun_id.to_string(),
            attempt: c.attempt_id.to_string(),
            fence: c.fence,
            invocation: c.invocation_id.to_string(),
            canonical_digest: c.canonical_binding_digest,
            binding_digest: c.binding_digest,
            binding: c.binding.clone(),
            owner: c.native_owner_id,
            generation: c.native_owner_generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Area {
    pub version: u8,
    pub role: String,
    pub context: Context,
    pub writer_pid: u32,
    pub nested: String,
    pub authority: [u8; 16],
    pub lineage: String,
    pub project: String,
    pub workspace: String,
    pub principal: String,
    pub node: String,
    pub epoch: u64,
    pub area: Vec<u8>,
    pub command_digest: [u8; 32],
    pub capture: Capture,
    pub trust_status: String,
    pub trust_epoch: u64,
    pub trust_revision: u64,
    pub trust_mask: u32,
}
impl Area {
    pub fn validate(&self, root: &Path, context: &Context) {
        assert_eq!(self.version, 1);
        assert_eq!(self.role, "writer");
        assert_eq!(&self.context, context);
        context.assert_controller();
        assert!(self.writer_pid > 0);
        runne_domain::id::validate_uuid_v7_bytes(&self.authority).unwrap();
        let lineage: runne_domain::id::EventLogLineageId = self.lineage.parse().unwrap();
        assert_eq!(lineage.to_string(), self.lineage);
        let project: ProjectId = self.project.parse().unwrap();
        let workspace: WorkspaceId = self.workspace.parse().unwrap();
        assert_eq!(project.to_string(), self.project);
        assert_eq!(workspace.to_string(), self.workspace);
        let principal = runne_api::ApiPrincipalId::new(self.principal.clone()).unwrap();
        assert_eq!(principal.as_str(), "capture-owner");
        assert_eq!(
            self.node,
            uuid::Uuid::from_bytes(self.authority).to_string()
        );
        assert!(self.epoch > 0 && self.capture.fence > 0 && self.capture.generation > 0);
        assert_ne!(self.capture.owner, [0; 16]);
        assert!(!self.capture.binding.is_empty());
        assert_eq!(self.area.len(), 100);
        let encoded = self.area_identity().to_bytes();
        assert_eq!(&encoded[52..68], self.identity().taskrun_id.as_bytes());
        assert_eq!(&encoded[68..84], self.identity().attempt_id.as_bytes());
        let invocation: InvocationId = self.capture.invocation.parse().unwrap();
        assert_eq!(invocation.to_string(), self.capture.invocation);
        assert_eq!(&encoded[84..100], invocation.as_bytes());
        self.trust_record();
        self.daemon(root);
    }
    pub fn identity(&self) -> TaskRunAssignmentIdentity {
        let task: TaskRunId = self.capture.task.parse().unwrap();
        let attempt: AttemptId = self.capture.attempt.parse().unwrap();
        assert_eq!(task.to_string(), self.capture.task);
        assert_eq!(attempt.to_string(), self.capture.attempt);
        TaskRunAssignmentIdentity {
            taskrun_id: task,
            attempt_id: attempt,
            fence: TaskRunFence(self.capture.fence),
            node_id: ExecutionNodeId(self.node.clone()),
            node_epoch: self.epoch,
        }
    }
    pub fn area_identity(&self) -> ManagedAreaIdentity {
        assert_eq!(self.area.len(), 100);
        ManagedAreaIdentity::from_bytes(&self.area).unwrap()
    }
    pub fn binding(&self) -> ManagedAreaBinding {
        let id = self.identity();
        let invocation: InvocationId = self.capture.invocation.parse().unwrap();
        ManagedAreaBinding::new(
            *id.taskrun_id.as_bytes(),
            *id.attempt_id.as_bytes(),
            *invocation.as_bytes(),
        )
        .unwrap()
    }
    pub fn daemon(&self, root: &Path) -> PathBuf {
        paths::component(&self.nested);
        let nested = root.join(&self.nested);
        for path in [
            nested.clone(),
            nested.join("runtime"),
            nested.join("runtime/daemon"),
        ] {
            paths::directory(&path);
            assert!(path.starts_with(root));
        }
        nested.join("runtime/daemon")
    }
    pub fn trust_record(&self) -> ProjectTrustRecord {
        assert_eq!(self.trust_status, "Trusted");
        assert!(self.trust_epoch > 0 && self.trust_revision > 0);
        ProjectTrustRecord {
            status: ProjectTrustStatus::Trusted,
            instance_epoch: self.trust_epoch,
            revision: self.trust_revision,
            managed_deny_mask: self.trust_mask,
        }
    }
}
