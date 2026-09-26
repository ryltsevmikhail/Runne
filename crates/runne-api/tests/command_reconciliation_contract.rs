use runne_api::{
    ApiPrincipalId, AuthoritativeCommandOutcome, AuthoritativeTextGenerationOutcome,
    AuthoritativeTextGenerationOutcomeRef, CanonicalConversationMessage, CanonicalMessageRole,
    CanonicalMessageText, CommandReconciliationContext, CommandReconciliationDisposition,
    CommandReconciliationHostError, CommandReconciliationWitness, CommandReconciliationWitnessRef,
    ConversationCreatedAck, ProjectCommandAck, ProjectWorkspaceDisplayNameInput,
    ReconciliationOperation,
};
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, ProjectId, WorkspaceId};
use runne_domain::{
    conversation::GenerationFailureReason,
    id::{AttemptId, MessageId, TaskRunId},
};

fn command_id() -> CommandId {
    "018f47a2-4f8c-7b52-8c35-7a3a14c2d901".parse().unwrap()
}

#[test]
fn text_only_witness_has_distinct_scope_tag_but_existing_create_operation() {
    let witness = CommandReconciliationWitness::create_text_only_conversation(
        conversation_id(),
        workspace_id(),
    );
    assert_eq!(
        witness.operation(),
        ReconciliationOperation::CreateConversation
    );
    assert!(matches!(
        witness.view(),
        CommandReconciliationWitnessRef::CreateTextOnlyConversation {
            conversation_id: actual_conversation,
            workspace_id: actual_workspace,
        } if actual_conversation == conversation_id() && actual_workspace == workspace_id()
    ));
}

fn project_id() -> ProjectId {
    "018f47a2-4f8c-7b52-8c35-7a3a14c2d902".parse().unwrap()
}

fn workspace_id() -> WorkspaceId {
    "018f47a2-4f8c-7b52-8c35-7a3a14c2d903".parse().unwrap()
}

fn conversation_id() -> ConversationId {
    "018f47a2-4f8c-7b52-8c35-7a3a14c2d904".parse().unwrap()
}

#[test]
fn reconciliation_context_owns_identity_and_witnesses_cover_exactly_nine_commands() {
    let context = CommandReconciliationContext::new(
        command_id(),
        IdempotencyKey::new("reconcile-key").unwrap(),
        ApiPrincipalId::new("owner").unwrap(),
    );
    assert_eq!(context.command_id(), command_id());
    assert_eq!(context.principal().as_str(), "owner");

    let witnesses = [
        CommandReconciliationWitness::create_project(project_id(), name("Project")),
        CommandReconciliationWitness::archive_project(project_id(), 1),
        CommandReconciliationWitness::delete_project(project_id(), 1),
        CommandReconciliationWitness::rename_project(project_id(), 1, name("Renamed")),
        CommandReconciliationWitness::create_workspace(
            workspace_id(),
            project_id(),
            name("Workspace"),
        ),
        CommandReconciliationWitness::bind_workspace_root(workspace_id(), 1, [7; 32]),
        CommandReconciliationWitness::open_workspace(workspace_id(), 1),
        CommandReconciliationWitness::create_conversation(conversation_id(), workspace_id()),
        CommandReconciliationWitness::generate_conversation_text(
            conversation_id(),
            1,
            CanonicalMessageText::new("hello").unwrap(),
        ),
    ];
    let operations = witnesses.map(|witness| witness.operation());
    assert_eq!(
        operations,
        [
            ReconciliationOperation::CreateProject,
            ReconciliationOperation::ArchiveProject,
            ReconciliationOperation::DeleteProject,
            ReconciliationOperation::RenameProject,
            ReconciliationOperation::CreateWorkspace,
            ReconciliationOperation::BindWorkspaceRoot,
            ReconciliationOperation::OpenWorkspace,
            ReconciliationOperation::CreateConversation,
            ReconciliationOperation::GenerateConversationText,
        ]
    );
}

#[test]
fn reconciliation_host_errors_remain_closed_and_redacted() {
    assert_eq!(
        CommandReconciliationHostError::Conflict.code(),
        "command_conflict"
    );
    assert_eq!(
        CommandReconciliationHostError::Backpressure.code(),
        "runtime_backpressure"
    );
    assert_eq!(
        CommandReconciliationHostError::Unavailable.code(),
        "runtime_unavailable"
    );
    assert_eq!(
        CommandReconciliationHostError::InvariantViolation.code(),
        "runtime_invariant_violation"
    );
}

#[test]
fn reconciliation_disposition_exposes_only_typed_durable_outcomes() {
    let project = AuthoritativeCommandOutcome::project_archived(ProjectCommandAck {
        project_id: project_id(),
        new_version: 2,
    });
    let conversation = AuthoritativeCommandOutcome::conversation_created(ConversationCreatedAck {
        conversation_id: conversation_id(),
        workspace_id: workspace_id(),
        stream_version: 1,
        committed_at: runne_api::NonNegativeUnixMillis::new(1).unwrap(),
    });
    assert!(
        CommandReconciliationDisposition::durably_recorded(&witness_archive(), project)
            .unwrap()
            .outcome()
            .is_some()
    );
    assert!(
        CommandReconciliationDisposition::durably_recorded(&witness_conversation(), conversation)
            .unwrap()
            .outcome()
            .is_some()
    );
    assert!(
        CommandReconciliationDisposition::not_committed_retryable().is_not_committed_retryable()
    );
    assert!(CommandReconciliationDisposition::indeterminate().is_indeterminate());
}

#[test]
fn durable_disposition_rejects_outcome_from_another_operation() {
    let outcome = AuthoritativeCommandOutcome::project_archived(ProjectCommandAck {
        project_id: project_id(),
        new_version: 2,
    });
    assert_eq!(
        CommandReconciliationDisposition::durably_recorded(&witness_conversation(), outcome),
        Err(CommandReconciliationHostError::InvariantViolation)
    );
}

#[test]
fn reconciliation_disposition_remains_pointer_sized_for_large_outcomes() {
    assert!(
        std::mem::size_of::<CommandReconciliationDisposition>() <= 2 * std::mem::size_of::<usize>()
    );
}

#[test]
fn prohibited_input_terminal_remains_distinct_in_the_borrowed_view() {
    let outcome = AuthoritativeTextGenerationOutcome::ProhibitedInputRejected {
        conversation_id: conversation_id(),
        taskrun_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2d905"
            .parse::<TaskRunId>()
            .unwrap(),
        attempt_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2d906"
            .parse::<AttemptId>()
            .unwrap(),
        conversation_stream_version: 3,
        taskrun_stream_version: 5,
        user_message: CanonicalConversationMessage {
            message_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2d907"
                .parse::<MessageId>()
                .unwrap(),
            role: CanonicalMessageRole::User,
            taskrun_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2d905".parse().unwrap(),
            attempt_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2d906".parse().unwrap(),
            text: "hello".into(),
            committed_at: runne_api::NonNegativeUnixMillis::new(1).unwrap(),
        },
        reserved_assistant_message_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2d908".parse().unwrap(),
        reason: GenerationFailureReason::ProviderOutputRejected,
    };
    assert!(matches!(
        outcome.view(),
        AuthoritativeTextGenerationOutcomeRef::ProhibitedInputRejected { .. }
    ));
}

fn name(value: &str) -> ProjectWorkspaceDisplayNameInput {
    ProjectWorkspaceDisplayNameInput::new(value.into()).unwrap()
}

fn witness_archive() -> CommandReconciliationWitness {
    CommandReconciliationWitness::archive_project(project_id(), 1)
}

fn witness_conversation() -> CommandReconciliationWitness {
    CommandReconciliationWitness::create_conversation(conversation_id(), workspace_id())
}
