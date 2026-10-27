//! Shared checked test binding construction; supplies no approval authority.
use super::super::fixture::Fixture;
use crate::{
    ProjectTrustStore,
    store::{ManagedIdentityMetadata, PermissionModeAuthorityContext, StoreTransaction},
};
use runne_api::ApiPrincipalId;
use runne_application::{
    permission_modes::*,
    ports::*,
    project_trust::{ProjectTrustPersistence, ProjectTrustProjectId},
};
use runne_domain::{
    id::{IntegrityDigest, InvocationId, ProjectId},
    task_run::TaskRunLocalCommand,
};
use runne_platform::local_command_linux::{
    LinuxCompositeScopeAdmission, PermissionTargetObservationV1,
};
use std::fs::File;

pub(in super::super) struct BindingContext<'a> {
    pub store: &'a StoreTransaction,
    pub trust: &'a ProjectTrustStore,
    pub native: &'a LinuxCompositeScopeAdmission,
    pub held: &'a File,
    pub project: ProjectId,
    pub scope: PermissionScope,
    pub principal: ApiPrincipalId,
}
impl<'a> BindingContext<'a> {
    pub fn from_fixture(f: &'a Fixture) -> Self {
        Self {
            store: &f.store,
            trust: &f.trust,
            native: &f.native,
            held: &f.held,
            project: f.project,
            scope: f.scope.clone(),
            principal: f.principal.clone(),
        }
    }
    fn trust_id(&self) -> ProjectTrustProjectId {
        ProjectTrustProjectId::from_bytes(self.project.into_bytes())
    }
}
pub(in super::super) struct BindingRequest {
    pub command: TaskRunLocalCommand,
    pub assignment: TaskRunAssignmentIdentity,
    pub claim_stream_version: u64,
    pub observation: PermissionTargetObservationV1,
    pub invocation_id: InvocationId,
    pub expires_at_unix_ms: i64,
}
pub(in super::super) fn build(
    f: &BindingContext<'_>,
    request: BindingRequest,
) -> LocalCommandPermissionBindingV1 {
    let BindingRequest {
        command,
        assignment,
        claim_stream_version,
        observation,
        invocation_id,
        expires_at_unix_ms,
    } = request;
    let taskrun_id = assignment.taskrun_id;
    let lease = f.trust.acquire_effect_lease(f.trust_id()).unwrap();
    let authority =
        PermissionModeAuthorityContext::new(&f.principal, f.trust_id(), lease.as_ref(), None);
    let selected = f
        .store
        .load_permission_mode_selection_with_managed_identity(&f.scope, &f.principal, &authority)
        .unwrap();
    let ManagedIdentityMetadata::ClosedRulesV2(managed) = selected.identity else {
        panic!("closed current identity")
    };
    let scope = CompositeEffectScope {
        permission_scope: f.scope.clone(),
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions: [
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]
            .into_iter()
            .collect(),
        },
        network: NetworkScope::None,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(
            f.trust_id(),
            &managed.snapshot,
        )
        .unwrap(),
        children: ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
        lifetime_ms: 120_000,
        containment: ContainmentStrategy::SameUserCompositeV1,
        protected_control_plane_policy_digest: f
            .native
            .protected_control_plane_policy_digest_v2(NetworkScope::None)
            .unwrap(),
    };
    let approval = ApprovalBinding {
        action: PermissionAction::ProcessStart,
        normalized_arguments_digest: IntegrityDigest::from_bytes(
            *observation.normalized_arguments_digest(),
        ),
        tool_schema_digest: IntegrityDigest::from_bytes(*observation.schema_digest()),
        principal_id: f.principal.clone(),
        invocation: InvocationIdentity {
            task_run_id: taskrun_id,
            attempt_id: assignment.attempt_id,
            invocation_id,
        },
        target_identity_digest: IntegrityDigest::from_bytes(*observation.target_identity()),
        target_version: observation.target_version(),
        environment_digest: IntegrityDigest::from_bytes(*observation.environment_digest()),
        cwd_identity_digest: IntegrityDigest::from_bytes(*observation.cwd_identity()),
        executable_digest: Some(IntegrityDigest::from_bytes(
            *observation.executable_digest(),
        )),
        composite_scope_digest: scope.digest().unwrap(),
        containment_version: scope.containment,
        relevant_policy_digest: scope.managed_policy.policy_digest(),
        expires_at_unix_ms,
    };
    let binding = LocalCommandPermissionBindingV1::checked(LocalCommandPermissionBindingInputV1 {
        selection: selected.selection,
        assignment,
        claim_stream_version,
        invocation_id,
        project_id: f.project,
        project_version: managed.project_version,
        workspace_version: 2,
        admitted_root_version: 2,
        held_root_identity_digest: LinuxCompositeScopeAdmission::workspace_root_identity(&f.held)
            .unwrap(),
        command_intent_digest: IntegrityDigest::from_bytes(command.intent_digest()),
        command,
        approval,
        scope,
        closed_rules_snapshot: managed.snapshot,
        closed_rules_digest: managed.canonical_digest,
        limits: LocalInvocationLimitsV1::checked(65536, 65536, 120_000).unwrap(),
    })
    .unwrap();
    drop(lease); // capture owns a new sidecar lease before Store writer and root fence.
    binding
}
