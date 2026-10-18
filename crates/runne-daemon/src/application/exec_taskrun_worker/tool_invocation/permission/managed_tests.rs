use super::managed::{durable_admission_facts_match, persisted_binding_matches};
use runne_api::ApiPrincipalId;
use runne_application::permission_modes::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, EffectBudget,
    FilesystemPermission, FilesystemPosture, FilesystemRoot, FilesystemScope,
    ManagedPolicyCoverage, NetworkScope, PermissionMode, PermissionScope, admit_invocation_scope,
};
use runne_application::ports::RuntimeAuthorityId;
use runne_domain::id::{AttemptId, CycleId, IntegrityDigest, TaskRunId, WorkspaceId};
use runne_platform::local_command_linux::LinuxCompositeScopeAdmission;
use runne_store::store::taskrun_tool_invocation::{
    ToolInvocationBindingV1, ToolInvocationKey, ToolPermissionAdmissionV1,
    ToolPermissionDecisionSource, ToolSourceRef,
};
use std::collections::BTreeSet;

#[test]
fn redacted_store_binding_readback_matches_exact_semantic_digest() {
    let mut current = binding();
    let mut saved_readback = current.clone();
    // Store::load_taskrun_tool_invocation clears this encrypted payload field.
    saved_readback.canonical_arguments.clear();
    assert!(persisted_binding_matches(&saved_readback, &current));
    assert!(!persisted_binding_matches(&current, &current));

    current.target_name = "changed.txt".into();
    assert!(!persisted_binding_matches(&saved_readback, &current));
}

#[test]
fn a_fresh_native_handle_cannot_reuse_saved_human_admission() {
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::File::open(directory.path()).unwrap();
    let native = LinuxCompositeScopeAdmission::new(&[&root]).unwrap();
    let identity = LinuxCompositeScopeAdmission::workspace_root_identity(&root).unwrap();
    let workspace = WorkspaceId::from_bytes([5; 16]);
    let scope = CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: RuntimeAuthorityId("runtime".into()),
            principal_id: ApiPrincipalId::new("owner").unwrap(),
            workspace_id: workspace,
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BoundedRoots(BTreeSet::from([FilesystemRoot::new(
                identity,
                Vec::new(),
            )
            .unwrap()])),
            permissions: BTreeSet::from([
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
            ]),
        },
        network: NetworkScope::None,
        managed_policy: ManagedPolicyCoverage::Unrestricted {
            policy_digest: IntegrityDigest::from_bytes([6; 32]),
        },
        children: ChildDelegationScope::None,
        budget: EffectBudget {
            max_operations: Some(1),
            max_bytes: Some(8192),
        },
        lifetime_ms: 120_000,
        containment: ContainmentStrategy::WorkspaceBoundV1,
        protected_control_plane_policy_digest: native.protected_control_plane_policy_digest(),
    };
    let original = admit_invocation_scope(&scope, &native).unwrap();
    let reminted = admit_invocation_scope(&scope, &native).unwrap();
    assert_ne!(original.platform_handle_id(), reminted.platform_handle_id());
    assert!(!durable_admission_facts_match(
        &admission(&scope, *original.platform_handle_id().as_bytes()),
        &admission(&scope, *reminted.platform_handle_id().as_bytes()),
    ));
}

fn admission(scope: &CompositeEffectScope, handle: [u8; 32]) -> ToolPermissionAdmissionV1 {
    ToolPermissionAdmissionV1 {
        key: binding().key,
        runtime_authority_id: "runtime".into(),
        principal_id: "owner".into(),
        workspace_id: scope.permission_scope.workspace_id,
        selected_mode: PermissionMode::AskAlways,
        authorization_revision: 1,
        managed_policy_version: 1,
        managed_policy_digest: IntegrityDigest::from_bytes([7; 32]),
        composite_scope_digest: IntegrityDigest::from_bytes(*scope.digest().unwrap().as_bytes()),
        containment: scope.containment,
        native_scope_handle: IntegrityDigest::from_bytes(handle),
        decision_source: ToolPermissionDecisionSource::Human,
        relevant_policy_digest: scope.managed_policy.policy_digest(),
        expires_at_unix_ms: 1000,
    }
}

fn binding() -> ToolInvocationBindingV1 {
    let mut value = ToolInvocationBindingV1 {
        key: ToolInvocationKey {
            taskrun_id: TaskRunId::from_bytes([1; 16]),
            attempt_id: AttemptId::from_bytes([2; 16]),
            cycle_id: CycleId::from_bytes([3; 16]),
            proposal_index: 4,
        },
        expected_taskrun_version: 5,
        call_id: "call-a".into(),
        tool_name: "workspace.file.create_new".into(),
        tool_revision: "1".into(),
        schema_digest: IntegrityDigest::from_bytes([6; 32]),
        canonical_arguments: br#"{"path":"file.txt","content_base64":"YQ=="}"#.to_vec(),
        arguments_digest: IntegrityDigest::from_bytes([0; 32]),
        semantic_digest: IntegrityDigest::from_bytes([0; 32]),
        sources: vec![ToolSourceRef {
            dispatch_attempt_id: [7; 16],
            sequence: 1,
            event_kind: 5,
            terminal: true,
            plaintext_digest: IntegrityDigest::from_bytes([8; 32]),
            profile_digest: IntegrityDigest::from_bytes([9; 32]),
            runtime_generation: 1,
        }],
        environment_id: "linux-agent-tools-v1".into(),
        environment_revision: "1".into(),
        root_identity: IntegrityDigest::from_bytes([10; 32]),
        root_revision: 1,
        target_name: "file.txt".into(),
        target_precondition: None,
        approval_id: [11; 16],
        principal_id: "owner".into(),
        approval_principal_id: "owner".into(),
        approval_action: "workspace.tool.invoke".into(),
        approval_resource: "workspace:file.txt".into(),
        approval_digest: IntegrityDigest::from_bytes([12; 32]),
        policy_revision: 1,
        approval_expires_at: 1000,
        round_index: 0,
    };
    value.refresh_digests();
    value
}
