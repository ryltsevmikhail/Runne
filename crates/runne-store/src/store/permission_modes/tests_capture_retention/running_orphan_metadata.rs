//! Durable original assignment data; no postexit Cut or reconstructed child.
pub(super) use super::capture::Capture;
use super::context::CaseContext;
use super::fixture_paths;
use super::model::{ContextRecord, pid};
use runne_application::ports::{ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence};
use runne_application::project_trust::{ProjectTrustRecord, ProjectTrustStatus};
use runne_domain::id::{AttemptId, InvocationId, ProjectId, TaskRunId, WorkspaceId};
use runne_platform::process_managed_area::{ManagedAreaBinding, ManagedAreaIdentity};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Kind {
    Original,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Area {
    pub version: u8,
    pub kind: Kind,
    pub context: ContextRecord,
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
    pub(super) fn validate(&self, context: &CaseContext) {
        context.check_roots();
        assert_eq!(self.version, 1);
        assert_eq!(self.context, context.record);
        self.context.validate();
        pid(self.writer_pid);
        assert_ne!(self.writer_pid, context.record.collector);
        match self.kind {
            Kind::Original => assert_ne!(self.writer_pid, context.record.supervisor),
            Kind::Control => assert_eq!(self.writer_pid, context.record.supervisor),
        }
        runne_domain::id::validate_uuid_v7_bytes(&self.authority).unwrap();
        let lineage: runne_domain::id::EventLogLineageId = self.lineage.parse().unwrap();
        assert_eq!(lineage.to_string(), self.lineage);
        let project: ProjectId = self.project.parse().unwrap();
        let workspace: WorkspaceId = self.workspace.parse().unwrap();
        assert_eq!(project.to_string(), self.project);
        assert_eq!(workspace.to_string(), self.workspace);
        assert_eq!(
            runne_api::ApiPrincipalId::new(self.principal.clone())
                .unwrap()
                .as_str(),
            "capture-owner"
        );
        assert_eq!(
            self.node,
            uuid::Uuid::from_bytes(self.authority).to_string()
        );
        assert!(self.epoch > 0 && self.capture.fence > 0 && self.capture.generation > 0);
        assert_ne!(self.capture.owner, [0; 16]);
        assert!(!self.capture.binding.is_empty());
        let bytes = self.area_identity().to_bytes();
        let assignment = self.identity();
        assert_eq!(&bytes[52..68], assignment.taskrun_id.as_bytes());
        assert_eq!(&bytes[68..84], assignment.attempt_id.as_bytes());
        let invocation: InvocationId = self.capture.invocation.parse().unwrap();
        assert_eq!(invocation.to_string(), self.capture.invocation);
        assert_eq!(&bytes[84..100], invocation.as_bytes());
        self.trust_record();
        self.daemon(context);
    }

    pub(super) fn identity(&self) -> TaskRunAssignmentIdentity {
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

    pub(super) fn area_identity(&self) -> ManagedAreaIdentity {
        assert_eq!(self.area.len(), 100);
        ManagedAreaIdentity::from_bytes(&self.area).unwrap()
    }

    pub(super) fn binding(&self) -> ManagedAreaBinding {
        let assignment = self.identity();
        let invocation: InvocationId = self.capture.invocation.parse().unwrap();
        ManagedAreaBinding::new(
            *assignment.taskrun_id.as_bytes(),
            *assignment.attempt_id.as_bytes(),
            *invocation.as_bytes(),
        )
        .unwrap()
    }

    pub(super) fn daemon(&self, context: &CaseContext) -> PathBuf {
        assert_eq!(self.context, context.record);
        fixture_paths::component(&self.nested);
        let nested = context.root.path.join(&self.nested);
        for path in [
            &nested,
            &nested.join("runtime"),
            &nested.join("runtime/daemon"),
        ] {
            fixture_paths::directory(path, context);
        }
        nested.join("runtime/daemon")
    }

    pub(super) fn trust_record(&self) -> ProjectTrustRecord {
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
