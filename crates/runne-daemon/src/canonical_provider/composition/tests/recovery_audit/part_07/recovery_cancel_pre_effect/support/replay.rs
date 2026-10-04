use super::super::super::super::fixture::Harness;
use super::cancellation_state_on;
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, EventStore,
    ProviderPreEffectCancellationEvidence, TextGenerationReceipt,
};

pub(crate) struct ReplayPlan<'a> {
    pub(crate) text_service:
        &'a dyn runne_application::conversation_text_service::ConversationTextCommandService,
    pub(crate) context: &'a ApplicationCommandContext,
    pub(crate) replay_input: runne_application::commands::BeginClaimedConversationTextInput,
    pub(crate) started: TextGenerationReceipt,
    pub(crate) evidence: ProviderPreEffectCancellationEvidence,
    pub(crate) conversation_id: runne_domain::id::ConversationId,
    pub(crate) taskrun_id: runne_domain::id::TaskRunId,
    pub(crate) node_epoch: u64,
}

pub(crate) fn verify_replay_after_corruption_and_advance(harness: &Harness, plan: ReplayPlan<'_>) {
    let before_corruption = cancellation_state_on(
        &harness.writer_connection(),
        plan.taskrun_id,
        plan.conversation_id,
    );
    let expected_receipt = load_receipt(harness, plan.context);
    let writer = harness.writer_connection();
    writer
        .execute(
            "UPDATE taskrun_assignment_occupations SET node_epoch=node_epoch+1 WHERE taskrun_id=?1",
            [plan.taskrun_id.as_bytes()],
        )
        .unwrap();
    assert!(
        plan.text_service
            .begin_claimed_text(plan.context, plan.replay_input.clone())
            .is_err()
    );
    assert_eq!(
        cancellation_state_on(&writer, plan.taskrun_id, plan.conversation_id),
        before_corruption
    );
    assert_eq!(load_receipt(harness, plan.context), expected_receipt);
    writer
        .execute(
            "UPDATE taskrun_assignment_occupations SET node_epoch=?1 WHERE taskrun_id=?2",
            rusqlite::params![plan.node_epoch as i64, plan.taskrun_id.as_bytes()],
        )
        .unwrap();

    let conversation_head = harness
        .store
        .load_conversation(plan.conversation_id)
        .unwrap();
    plan.text_service
        .begin_text(
            &crate::canonical_provider::composition::tests::command_context(
                "018f2e3a-7000-7000-8000-000000000151",
                "advance-after-cancel",
            ),
            runne_application::commands::BeginConversationTextInput {
                conversation_id: plan.conversation_id,
                expected_version: conversation_head.current_version,
                text: runne_domain::message::MessageText::new("new active generation").unwrap(),
            },
        )
        .unwrap();
    let old_fence: i64 = harness
        .query_connection()
        .query_row(
            "SELECT fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
            [plan.conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    harness
        .store
        .take_control_conversation_writer_lease(
            plan.conversation_id.as_bytes(),
            "later-principal",
            old_fence as u64,
        )
        .unwrap();

    let before_replay = snapshot(harness, plan.context, plan.conversation_id, plan.taskrun_id);
    let begin_receipt = plan
        .text_service
        .begin_claimed_text(plan.context, plan.replay_input.clone())
        .unwrap();
    assert_eq!(begin_receipt, expected_receipt);
    assert_eq!(
        snapshot(harness, plan.context, plan.conversation_id, plan.taskrun_id),
        before_replay
    );

    let finish_receipt = plan.text_service
        .finish_text(
            plan.context,
            runne_application::commands::FinishConversationTextInput {
                original: plan.replay_input.original,
                started: plan.started,
                completion: runne_application::commands::ConversationTextCompletion::PreEffectRejectedCancellation {
                    evidence: plan.evidence,
                },
            },
        )
        .unwrap();
    assert_eq!(finish_receipt, expected_receipt);
    assert_eq!(
        snapshot(harness, plan.context, plan.conversation_id, plan.taskrun_id),
        before_replay
    );
}

fn load_receipt(harness: &Harness, context: &ApplicationCommandContext) -> TextGenerationReceipt {
    harness
        .store
        .load_text_generation_receipt_by_command(context.command_id, &context.idempotency_key)
        .unwrap()
}

type ReplaySnapshot = (
    String,
    u64,
    Option<runne_domain::id::EventId>,
    String,
    u64,
    Option<runne_domain::id::EventId>,
    TextGenerationReceipt,
    String,
    i64,
);

fn snapshot(
    harness: &Harness,
    context: &ApplicationCommandContext,
    conversation_id: runne_domain::id::ConversationId,
    taskrun_id: runne_domain::id::TaskRunId,
) -> ReplaySnapshot {
    let conversation = harness.store.load_conversation(conversation_id).unwrap();
    let taskrun = harness.store.load_task_run(taskrun_id).unwrap();
    let connection = harness.query_connection();
    let (owner, fence): (String, i64) = connection
        .query_row(
            "SELECT owner_principal,fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
            [conversation_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    (
        format!("{:?}", conversation.events),
        conversation.current_version,
        conversation.last_event_id,
        format!("{:?}", taskrun.events),
        taskrun.current_version,
        taskrun.last_event_id,
        load_receipt(harness, context),
        owner,
        fence,
    )
}
