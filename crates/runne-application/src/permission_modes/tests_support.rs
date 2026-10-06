fn input(
    mode: PermissionMode,
    action: PermissionAction,
    facts: ResourceFacts,
    scope: CompositeEffectScope,
) -> PolicyEvaluationInput {
    let effective_scope = scope.clone();
    let binding = candidate(action, &scope);
    let scope_digest = scope.digest().unwrap();
    PolicyEvaluationInput {
        selection: selection(mode),
        effective: admit_effective_mode(mode, PresetVersion::V1, &effective_scope, &MockAdmission)
            .unwrap(),
        effective_scope,
        invocation: InvocationPolicyRequest {
            action,
            resource: facts,
            composite_scope: scope.clone(),
            candidate_binding: binding,
            approved_binding: None,
            native_admission: Some(admit_invocation_scope(&scope, &MockAdmission).unwrap()),
        },
        managed: ManagedPolicyEvaluation {
            scope_digest,
            policy_digest: scope.managed_policy.policy_digest(),
            disposition: ManagedDisposition::Allow,
        },
        now_unix_ms: 100,
    }
}

fn full_access_input(
    mode: PermissionMode,
    action: PermissionAction,
    facts: ResourceFacts,
) -> PolicyEvaluationInput {
    let mut scope = full_scope();
    scope.managed_policy = ManagedPolicyCoverage::Restricted {
        policy_digest: digest(31),
    };
    input(mode, action, facts, scope)
}

fn selection(mode: PermissionMode) -> ModeSelection {
    ModeSelection {
        scope: permission_scope(),
        selected_mode: mode,
        preset_version: PresetVersion::V1,
        authorization_revision: 1,
        expires_at_unix_ms: None,
    }
}

fn permission_scope() -> PermissionScope {
    PermissionScope {
        runtime_authority_id: crate::ports::RuntimeAuthorityId("runtime-a".into()),
        principal_id: runne_api::ApiPrincipalId::new("user:alice").unwrap(),
        workspace_id: workspace(1),
    }
}

fn bounded_scope() -> CompositeEffectScope {
    let root = FilesystemRoot::new(digest(11), vec![]).unwrap();
    let mut permissions = BTreeSet::new();
    permissions.extend([
        FilesystemPermission::Read,
        FilesystemPermission::Create,
        FilesystemPermission::Write,
        FilesystemPermission::Delete,
    ]);
    CompositeEffectScope {
        permission_scope: permission_scope(),
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BoundedRoots(BTreeSet::from([root])),
            permissions,
        },
        network: NetworkScope::Brokered {
            policy_digest: digest(23),
        },
        managed_policy: ManagedPolicyCoverage::Unrestricted {
            policy_digest: digest(31),
        },
        children: ChildDelegationScope::None,
        budget: EffectBudget {
            max_operations: Some(5),
            max_bytes: Some(4096),
        },
        lifetime_ms: 30_000,
        containment: ContainmentStrategy::WorkspaceBoundV1,
        protected_control_plane_policy_digest: digest(55),
    }
}

fn full_scope() -> CompositeEffectScope {
    let mut scope = bounded_scope();
    scope.filesystem.posture = FilesystemPosture::BroadSameUser;
    scope.network = NetworkScope::BroadSameUser;
    scope.children = ChildDelegationScope::Unbounded;
    scope.containment = ContainmentStrategy::SameUserCompositeV1;
    scope
}

fn candidate(action: PermissionAction, scope: &CompositeEffectScope) -> ApprovalBinding {
    ApprovalBinding {
        action,
        normalized_arguments_digest: digest(1),
        tool_schema_digest: digest(2),
        principal_id: scope.permission_scope.principal_id.clone(),
        invocation: InvocationIdentity {
            task_run_id: id_task(),
            attempt_id: id_attempt(),
            invocation_id: id_invocation(),
        },
        target_identity_digest: digest(3),
        target_version: 1,
        environment_digest: digest(4),
        cwd_identity_digest: digest(5),
        executable_digest: (action == PermissionAction::ProcessStart).then(|| digest(6)),
        composite_scope_digest: scope.digest().unwrap(),
        containment_version: scope.containment,
        relevant_policy_digest: scope.managed_policy.policy_digest(),
        expires_at_unix_ms: 1000,
    }
}

fn safe_target() -> ResourceFacts {
    let mut facts = ResourceFacts::safe_workspace_read();
    facts.resolved_path = Some(FilesystemRoot::new(digest(11), vec!["file.txt".into()]).unwrap());
    facts
}

fn safe_create_target() -> ResourceFacts {
    let mut facts = ResourceFacts::safe_workspace_create();
    facts.resolved_path = Some(FilesystemRoot::new(digest(11), vec!["new.txt".into()]).unwrap());
    facts
}

fn outside_safe_target() -> ResourceFacts {
    ResourceFacts {
        workspace: WorkspaceRelation::Outside,
        ..safe_target()
    }
}

fn unheld_outside_target() -> ResourceFacts {
    let mut facts = outside_safe_target();
    facts.resolved_path =
        Some(FilesystemRoot::new(digest(12), vec!["outside.txt".into()]).unwrap());
    facts
}

fn process_facts() -> ResourceFacts {
    ResourceFacts {
        resolution: ResolutionState::HeldSafe,
        ..ResourceFacts::unknown()
    }
}

fn digest(value: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([value; 32])
}
fn workspace(value: u8) -> WorkspaceId {
    let mut bytes = [value; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    WorkspaceId::from_bytes(bytes)
}
fn id_task() -> TaskRunId {
    TaskRunId::from_str("018f2e3a-7000-7000-8000-000000000001").unwrap()
}
fn id_attempt() -> AttemptId {
    AttemptId::from_str("018f2e3a-7000-7000-8000-000000000002").unwrap()
}
fn id_invocation() -> InvocationId {
    InvocationId::from_str("018f2e3a-7000-7000-8000-000000000003").unwrap()
}
