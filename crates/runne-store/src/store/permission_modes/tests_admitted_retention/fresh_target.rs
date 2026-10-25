use super::fixture::{Fixture, command_id, key, now};
use crate::store::{
    LocalCommandAttemptState, LocalCommandPermissionCaptureV1, ManagedIdentityMetadata,
    PermissionModeAuthorityContext,
};
use runne_application::{
    commands::{CommandOutcome, SubmitTaskRunInput},
    conversation_service::ConversationService,
    permission_modes::*,
    ports::*,
    project_trust::ProjectTrustPersistence,
    service::{ClaimTaskRunInput, TaskRunService},
};
use runne_domain::{
    event::Actor,
    id::{ConversationId, IntegrityDigest, InvocationId},
    task_run::{TaskRunExecutable, TaskRunInput, TaskRunLocalCommand},
};
use runne_platform::local_command_linux::{LinuxCompositeScopeAdmission, SealedExecutableSnapshot};

fn context(f: &Fixture, label: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command_id(),
        idempotency_key: key(&format!("{label}-{}", uuid::Uuid::now_v7())),
        principal_id: PrincipalId(f.principal.as_str().into()),
        actor: Actor::new("capture-test").unwrap(),
    }
}

pub(super) fn prepare(
    f: &Fixture,
) -> (
    LocalCommandPermissionBindingV1,
    runne_platform::local_command_linux::PreparedPermissionTargetV1,
) {
    let command = TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let path = f.root.path().join("workspace/tool");
    // A held bounded executable fixture is sealed, never executed.
    std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let snapshot =
        SealedExecutableSnapshot::from_held_file(&std::fs::File::open(path).unwrap()).unwrap();
    let prepared = f
        .store
        .local_permission_preparation()
        .unwrap()
        .prepare_target(command.clone(), &f.held, &f.held, snapshot)
        .unwrap();
    let observation = prepared.observation();
    let conversation_id = ConversationId::from_bytes(uuid::Uuid::now_v7().into_bytes());
    let conversation_context = context(f, "conversation");
    ConversationService::new(
        f.store.clone(),
        f.store.clone(),
        f.scope.runtime_authority_id.clone(),
    )
    .create_from_application(
        &conversation_context,
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id: f.scope.workspace_id,
            command_id: conversation_context.command_id,
            idempotency_key: conversation_context.idempotency_key.clone(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let service = TaskRunService::new(
        f.store.clone(),
        f.store.clone(),
        f.store.clone(),
        f.scope.runtime_authority_id.clone(),
    );
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id,
        new_version,
        ..
    } = service
        .submit_task_run(
            &context(f, "submit"),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id: f.scope.workspace_id,
                input: TaskRunInput::new("bounded capture".into())
                    .unwrap()
                    .with_local_command(command.clone())
                    .unwrap(),
            },
        )
        .unwrap()
    else {
        panic!("fresh V2 submission")
    };
    let (node, epoch) = {
        let writer = f.store.inner.writer.lock().unwrap();
        // Local node identity is the fresh Store authority, not a separate UUID.
        let bytes: Vec<u8> = writer
            .query_row(
                "SELECT authority_id FROM _authority WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let node = uuid::Uuid::from_slice(&bytes).unwrap();
        // Preserve one real Store node epoch for two fresh invocation assignments.
        let count: i64 = writer
            .query_row("SELECT count(*) FROM execution_nodes", [], |r| r.get(0))
            .unwrap();
        let registered = if count == 0 {
            None
        } else {
            crate::execution_node::eligible_local_linux_node(&writer).unwrap()
        };
        if let Some(registered) = registered {
            assert_eq!(registered.node_id, node.into_bytes());
            assert_eq!(registered.descriptor.capacity, 2);
            (node, registered.launch_generation)
        } else {
            let epoch = crate::schema::next_launch_generation(&writer).unwrap();
            crate::execution_node::register_local_linux_node(
                &writer,
                node.into_bytes(),
                epoch,
                crate::execution_node::LinuxNodeDescriptor { capacity: 2 },
                30,
            )
            .unwrap();
            (node, epoch)
        }
    };
    let TaskRunClaimResult::Committed(receipt) = service
        .claim_task_run(
            &context(f, "claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: new_version,
                node_id: ExecutionNodeId(node.to_string()),
                node_epoch: epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &f.store,
        )
        .unwrap()
    else {
        panic!("fresh claim")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: receipt.node_id,
        node_epoch: receipt.node_epoch,
        fence: receipt.fence,
    };
    let input = f
        .store
        .read_taskrun_execution_input(assignment.clone(), receipt.new_version)
        .unwrap();
    assert_eq!(input.input.local_command(), Some(&command));
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
    let invocation_id = InvocationId::from_bytes(uuid::Uuid::now_v7().into_bytes());
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
        expires_at_unix_ms: now() + 120_000,
    };
    let binding = LocalCommandPermissionBindingV1::checked(LocalCommandPermissionBindingInputV1 {
        selection: selected.selection,
        assignment,
        claim_stream_version: input.stream_version,
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
    (binding, prepared)
}

pub(super) fn capture(
    f: &Fixture,
) -> (
    LocalCommandPermissionBindingV1,
    LocalCommandPermissionCaptureV1,
    runne_platform::local_command_linux::PreparedPermissionTargetV1,
) {
    let (binding, prepared) = prepare(f);
    let observation = prepared.observation();
    let taskrun_id = binding.assignment().taskrun_id;
    let capture = f
        .store
        .capture_local_command_permission(&binding, observation)
        .unwrap();
    assert_eq!(
        capture.canonical_binding_digest,
        *binding.digest().as_bytes()
    );
    assert_eq!(capture.native_owner_id, *observation.owner_id());
    assert_eq!(
        capture.native_owner_generation,
        observation.owner_generation()
    );
    assert_eq!(capture.state, LocalCommandAttemptState::ApprovalPending);
    let route: (i64,i64,i64) = f.store.inner.reader.lock().unwrap().query_row("SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes WHERE taskrun_id=?1", [taskrun_id.as_bytes()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(route, (2, 3, 68));
    (binding, capture, prepared)
}
