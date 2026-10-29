use super::fixture::{Fixture, now};
use crate::store::LocalCommandPermissionCaptureV1;
use runne_application::{
    commands::{CommandOutcome, SubmitTaskRunInput},
    conversation_service::ConversationService,
    permission_modes::*,
    ports::*,
    service::{ClaimTaskRunInput, TaskRunService},
};
use runne_domain::{
    id::{ConversationId, InvocationId},
    task_run::{TaskRunExecutable, TaskRunInput, TaskRunLocalCommand},
};
#[path = "target_binding.rs"]
pub(super) mod binding;
#[path = "target_support.rs"]
mod support;
use support::context;

pub(super) fn prepare(
    f: &Fixture,
) -> (
    LocalCommandPermissionBindingV1,
    runne_platform::local_command_linux::PreparedPermissionTargetV1,
) {
    prepare_with_executable(f, vec!["tool".into()], b"#!/bin/sh\nexit 0\n")
}

// Native tests supply an installed ELF and exact argv before capture/approval.
pub(super) fn prepare_with_executable(
    f: &Fixture,
    argv: Vec<String>,
    executable: &[u8],
) -> (
    LocalCommandPermissionBindingV1,
    runne_platform::local_command_linux::PreparedPermissionTargetV1,
) {
    let command = TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
        ".".into(),
        argv,
        vec![],
    )
    .unwrap();
    prepare_with_command(f, command, executable)
}

// Structured intent is fixed before preparation, submission and capture.
pub(super) fn prepare_with_command(
    f: &Fixture,
    command: TaskRunLocalCommand,
    executable: &[u8],
) -> (
    LocalCommandPermissionBindingV1,
    runne_platform::local_command_linux::PreparedPermissionTargetV1,
) {
    let (binding, prepared, _) = prepare_with_command_recorded(f, command, executable, &f.store);
    (binding, prepared)
}

// Preserve call-time originals for the crash oracle; ordinary callers are unchanged.
pub(super) fn prepare_with_command_recorded<P: TaskRunClaimPort>(
    f: &Fixture,
    command: TaskRunLocalCommand,
    executable: &[u8],
    claim_port: &P,
) -> (
    LocalCommandPermissionBindingV1,
    runne_platform::local_command_linux::PreparedPermissionTargetV1,
    ConversationId,
) {
    let prepared = support::prepare(f, &command, executable);
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
        let epoch = crate::schema::next_launch_generation(&writer).unwrap();
        crate::execution_node::register_local_linux_node(
            &writer,
            node.into_bytes(),
            epoch,
            crate::execution_node::LinuxNodeDescriptor { capacity: 1 },
            30,
        )
        .unwrap();
        (node, epoch)
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
            claim_port,
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
    let binding = binding::build(
        &binding::BindingContext::from_fixture(f),
        binding::BindingRequest {
            command,
            assignment,
            claim_stream_version: input.stream_version,
            observation,
            invocation_id: InvocationId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
            expires_at_unix_ms: now() + 120_000,
        },
    );
    (binding, prepared, conversation_id)
}

pub(super) fn capture(
    f: &Fixture,
) -> (
    LocalCommandPermissionBindingV1,
    LocalCommandPermissionCaptureV1,
    runne_platform::local_command_linux::PreparedPermissionTargetV1,
) {
    support::capture(f)
}
