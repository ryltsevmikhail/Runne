//! Deterministic checked-data fixtures; none represent live owner authority.

use std::collections::BTreeSet;

use runne_api::ApiPrincipalId;
use runne_domain::{
    id::{AttemptId, IntegrityDigest, InvocationId, ProjectId, TaskRunId, WorkspaceId},
    task_run::{TaskRunExecutable, TaskRunLocalCommand},
};

use crate::{
    permission_modes::{
        ApprovalBinding, ContainmentStrategy, FilesystemPermission as Fs, InvocationIdentity,
        LocalCommandPermissionBindingInputV1, LocalCommandPermissionBindingV1,
        LocalInvocationLimitsV1, ModeSelection, NetworkScope, PermissionAction, PermissionMode,
        PermissionScope, RetainedAdmissionEvidenceV1, RetainedClockObservationV1,
        RetainedCurrentFactsV1, RetainedOriginalContextInputV1, RetainedOriginalContextV1,
        RetainedPhaseObservationV1, RetainedPolicyInputV1,
    },
    ports::{ExecutionNodeId, RuntimeAuthorityId, TaskRunAssignmentIdentity, TaskRunFence},
    project_trust::{
        ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId,
        ProjectTrustRecord, ProjectTrustStatus, managed_effect_policy_digest_v2,
    },
};

pub(crate) fn digest(byte: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([byte; 32])
}

fn uuid(byte: u8) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    bytes[15] = byte;
    bytes
}

pub(crate) fn snapshot(revision: u64) -> ProjectTrustEffectPolicySnapshot {
    ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Managed,
            instance_epoch: 9,
            revision,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::all_allow(),
    }
}

pub(super) fn selection_for(
    original: &LocalCommandPermissionBindingV1,
    mode: PermissionMode,
    revision: u64,
) -> ModeSelection {
    let mut selection = original.selection().clone();
    selection.selected_mode = mode;
    selection.authorization_revision = revision;
    selection
}

pub(crate) struct Fixture {
    pub original: LocalCommandPermissionBindingV1,
    pub context: RetainedOriginalContextV1,
    pub current: RetainedCurrentFactsV1,
    pub candidate: ApprovalBinding,
    pub resource: crate::permission_modes::ResourceFacts,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        Self::with_shape(
            ContainmentStrategy::SameUserCompositeV1,
            NetworkScope::BroadSameUser,
            [Fs::Read, Fs::Create, Fs::Write, Fs::Delete]
                .into_iter()
                .collect(),
            0,
        )
    }

    pub(crate) fn distinct() -> Self {
        Self::with_shape(
            ContainmentStrategy::SameUserCompositeV1,
            NetworkScope::BroadSameUser,
            [Fs::Read, Fs::Create, Fs::Write, Fs::Delete]
                .into_iter()
                .collect(),
            40,
        )
    }

    pub(crate) fn v2(network: NetworkScope, permissions: BTreeSet<Fs>) -> Self {
        Self::with_shape(
            ContainmentStrategy::SameUserCompositeV2,
            network,
            permissions,
            0,
        )
    }

    fn with_shape(
        containment: ContainmentStrategy,
        network: NetworkScope,
        permissions: BTreeSet<Fs>,
        identity_offset: u8,
    ) -> Self {
        let principal = ApiPrincipalId::new("retained-user").unwrap();
        let workspace_id = WorkspaceId::from_bytes(uuid(1));
        let project_id = ProjectId::from_bytes(uuid(2));
        let project = ProjectTrustProjectId::from_bytes(*project_id.as_bytes());
        let permission_scope = PermissionScope {
            runtime_authority_id: RuntimeAuthorityId("runtime-test".into()),
            principal_id: principal.clone(),
            workspace_id,
        };
        let selection = ModeSelection {
            scope: permission_scope.clone(),
            selected_mode: PermissionMode::FullAccess,
            preset_version: super::super::model::PresetVersion::V1,
            authorization_revision: 1,
            expires_at_unix_ms: Some(800_000),
        };
        let original_snapshot = snapshot(3);
        let original_scope = super::compatibility_tests::scope(
            permission_scope.clone(),
            project,
            original_snapshot,
            containment,
            network,
            permissions.clone(),
        );
        let taskrun_id = TaskRunId::from_bytes(uuid(3 + identity_offset));
        let attempt_id = AttemptId::from_bytes(uuid(4 + identity_offset));
        let invocation_id = InvocationId::from_bytes(uuid(5 + identity_offset));
        let assignment = TaskRunAssignmentIdentity {
            taskrun_id,
            attempt_id,
            node_id: ExecutionNodeId("node-a".into()),
            node_epoch: 2,
            fence: TaskRunFence(3),
        };
        let command = TaskRunLocalCommand::new(
            TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
            ".".into(),
            vec!["tool".into(), "--check".into()],
            vec![],
        )
        .unwrap();
        let scope_digest = original_scope.digest().unwrap();
        let approval = ApprovalBinding {
            action: PermissionAction::ProcessStart,
            normalized_arguments_digest: digest(6),
            tool_schema_digest: digest(7),
            principal_id: principal.clone(),
            invocation: InvocationIdentity {
                task_run_id: taskrun_id,
                attempt_id,
                invocation_id,
            },
            target_identity_digest: digest(8),
            target_version: 1,
            environment_digest: digest(9),
            cwd_identity_digest: digest(10),
            executable_digest: Some(digest(11)),
            composite_scope_digest: scope_digest,
            containment_version: containment,
            relevant_policy_digest: original_scope.managed_policy.policy_digest(),
            expires_at_unix_ms: 700_000,
        };
        let limits = LocalInvocationLimitsV1::checked(1024, 1024, 120_000).unwrap();
        let original =
            LocalCommandPermissionBindingV1::checked(LocalCommandPermissionBindingInputV1 {
                selection,
                assignment: assignment.clone(),
                claim_stream_version: 12,
                invocation_id,
                project_id,
                project_version: 15,
                workspace_version: 18,
                admitted_root_version: 20,
                held_root_identity_digest: digest(12),
                command_intent_digest: IntegrityDigest::from_bytes(command.intent_digest()),
                command,
                approval: approval.clone(),
                scope: original_scope,
                closed_rules_snapshot: original_snapshot,
                closed_rules_digest: IntegrityDigest::from_bytes(
                    managed_effect_policy_digest_v2(project, &original_snapshot).unwrap(),
                ),
                limits,
            })
            .unwrap();
        let coords = super::compatibility_tests::coordinates(
            &original,
            original_snapshot.record,
            principal.clone(),
            project_id,
        );
        let context = RetainedOriginalContextV1::checked(
            &original,
            RetainedOriginalContextInputV1 {
                original_binding_digest: original.digest(),
                capture_format_version: 1,
                source_record_version: 1,
                coordinates: coords.clone(),
                admission_clock: RetainedClockObservationV1 {
                    epoch: 50,
                    wall_unix_ms: 100_000,
                    monotonic_ms: 1_000,
                },
                selection_expiry_unix_ms: Some(800_000),
                invocation_deadline_unix_ms: 700_000,
            },
        )
        .unwrap();
        let current_snapshot = snapshot(4);
        let current_scope = super::compatibility_tests::scope(
            permission_scope.clone(),
            project,
            current_snapshot,
            containment,
            network,
            permissions,
        );
        let mut current_coords = coords;
        current_coords.trust_record = current_snapshot.record;
        let current = super::compatibility_tests::current_facts(
            &original,
            selection_for(&original, PermissionMode::FullAccess, 2),
            current_scope,
            project_id,
            current_snapshot,
            current_coords,
        );
        Self {
            original,
            context,
            current,
            candidate: approval,
            resource: crate::permission_modes::ResourceFacts {
                workspace: crate::permission_modes::WorkspaceRelation::Outside,
                sensitivity: crate::permission_modes::Sensitivity::Sensitive,
                size: crate::permission_modes::SizeBound::Unbounded,
                resolution: crate::permission_modes::ResolutionState::HeldSafe,
                resolved_path: None,
                target: crate::permission_modes::TargetState::Existing,
                object: crate::permission_modes::ObjectKind::Other,
                executable: true,
            },
        }
    }

    pub(crate) fn replace_current(
        &mut self,
        snapshot: ProjectTrustEffectPolicySnapshot,
        mode: PermissionMode,
        revision: u64,
    ) {
        let original_scope = self.original.scope();
        let project = ProjectTrustProjectId::from_bytes(*self.original.project_id().as_bytes());
        let scope = super::compatibility_tests::scope(
            original_scope.permission_scope.clone(),
            project,
            snapshot,
            original_scope.containment,
            original_scope.network,
            original_scope.filesystem.permissions.clone(),
        );
        let mut coordinates = self.current.coordinates.clone();
        coordinates.trust_record = snapshot.record;
        self.current = super::compatibility_tests::current_facts(
            &self.original,
            selection_for(&self.original, mode, revision),
            scope,
            self.original.project_id(),
            snapshot,
            coordinates,
        );
    }

    pub(crate) fn input(&self, phase: RetainedPhaseObservationV1) -> RetainedPolicyInputV1<'_> {
        RetainedPolicyInputV1 {
            original: &self.original,
            original_context: Some(&self.context),
            current: &self.current,
            original_identity_candidate: &self.candidate,
            admission: RetainedAdmissionEvidenceV1::Auto,
            selected_human_candidate: None,
            phase,
            action: PermissionAction::ProcessStart,
            resource: &self.resource,
        }
    }
}

pub(crate) fn full_allow_snapshot() -> ProjectTrustEffectPolicySnapshot {
    snapshot(4)
}
