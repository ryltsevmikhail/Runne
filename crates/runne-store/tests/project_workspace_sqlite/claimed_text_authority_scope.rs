use super::{claim::node_registration, submit_fence::submit_task_run, support::*};
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, BeginClaimedTextGenerationCommit, CommitError, ConversationRepository,
    ConversationTextRepository, EventStore, ExecutionNodeId, IdGenerator, IdempotencyScope,
    OperationTag, TaskRunAssignmentIdentity,
};
use runne_domain::event::{Sensitivity, UncommittedEvent};
use runne_domain::id::{AggregateId, ConversationId, WorkspaceId};
use runne_domain::message::MessageText;

#[test]
fn claimed_begin_rejects_foreign_runtime_scope_without_mutation() {
    let database = Database::new("claimed-text-foreign-authority");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let submitted = submit_task_run(&database, 0x41, "claimed-text-foreign-authority");
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submitted
    else {
        panic!("submit outcome expected")
    };
    let conversation_id = ConversationId::from_bytes(command(0x51).into_bytes());
    let (node, node_epoch) = node_registration(&database);
    let claim_context = task_context(0x52, "claim-foreign-authority");
    let claim = database
        .task_runs()
        .claim_task_run(
            &claim_context,
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    let runne_application::ports::TaskRunClaimResult::Committed(claim) = claim else {
        panic!("claim commits")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id,
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    let context = task_context(0x53, "claimed-begin-foreign-authority");
    let prompt = MessageText::new("test prompt").unwrap();
    let conversation = database.store.load_conversation(conversation_id).unwrap();
    let user_message_id = database.store.next_message_id().unwrap();
    let assistant_message_id = database.store.next_message_id().unwrap();
    let event = UncommittedEvent::from_parts(
        database.store.next_event_ids(1).unwrap().remove(0),
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        conversation.last_event_id,
        context.command_id,
        context.idempotency_key.clone(),
        1,
        context.actor.clone(),
        Sensitivity::Sensitive,
        runne_domain::conversation::ConversationEvent::UserMessageAppended {
            message_id: user_message_id,
            taskrun_id,
            attempt_id: assignment.attempt_id,
            text: prompt.clone(),
        },
    );
    let payload = BeginClaimedTextGenerationCommit {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId(
                "foreign-runtime-authority".into(),
            ),
            principal_id: context.principal_id,
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
        },
        command_fingerprint: CommandFingerprint::for_generate_conversation_text(
            &conversation_id,
            1,
            &prompt,
        ),
        expected_conversation_version: 1,
        expected_taskrun_version: claim.new_version,
        submitted_prompt: prompt,
        assignment: assignment.clone(),
        conversation_events: vec![event],
        receipt: runne_application::ports::TextGenerationReceipt {
            phase: runne_application::ports::TextGenerationPhase::Started,
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            taskrun_id,
            attempt_id: assignment.attempt_id,
            user_message_id,
            assistant_message_id,
            conversation_version: 2,
            taskrun_version: claim.new_version,
        },
    };
    let before = state(
        &database,
        taskrun_id,
        conversation_id,
        assignment.fence.0,
        context.command_id,
    );
    assert!(matches!(
        database.store.begin_claimed_text_generation(payload),
        Err(CommitError::StorageFailure(
            runne_application::ports::StorageFailureKind::IntegrityViolation
        ))
    ));
    assert_eq!(
        state(
            &database,
            taskrun_id,
            conversation_id,
            assignment.fence.0,
            context.command_id,
        ),
        before
    );
}

fn state(
    database: &Database,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: ConversationId,
    fence: u64,
    command_id: runne_domain::id::CommandId,
) -> (u64, u64, i64, i64, i64, i64) {
    let taskrun_version = database
        .store
        .load_task_run(taskrun_id)
        .unwrap()
        .current_version;
    let conversation_version = database
        .store
        .load_conversation(conversation_id)
        .unwrap()
        .current_version;
    let connection = database.connection();
    let receipts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM command_receipts WHERE command_id=?1",
            [command_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let events: i64 = connection
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    let occupations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), fence as i64],
            |row| row.get(0),
        )
        .unwrap();
    let writer_leases: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM conversation_writer_leases",
            [],
            |row| row.get(0),
        )
        .unwrap();
    (
        taskrun_version,
        conversation_version,
        events,
        receipts,
        occupations,
        writer_leases,
    )
}
