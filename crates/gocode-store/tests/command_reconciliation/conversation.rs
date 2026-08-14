use super::*;
use gocode_api::{
    AuthoritativeCommandOutcome, AuthoritativeTextGenerationOutcome, CanonicalMessageRole,
};
use gocode_application::ports::{ConversationRepository, TextGenerationPhase};
use gocode_domain::conversation::{Conversation, ConversationState};
use gocode_domain::message::MessageRole;

fn text_service(
    fixture: &Fixture,
) -> ConversationTextService<
    gocode_store::store::StoreTransaction,
    gocode_store::store::StoreTransaction,
> {
    ConversationTextService::new(
        fixture.store.clone(),
        fixture.store.clone(),
        RuntimeAuthorityId("authority".into()),
        guard(),
    )
}

fn begin(
    fixture: &Fixture,
    command_id: CommandId,
    text: &str,
) -> (
    ApplicationCommandContext,
    BeginConversationTextInput,
    gocode_application::ports::TextGenerationReceipt,
) {
    let command_context = application_context(command_id, "key");
    let original = BeginConversationTextInput {
        conversation_id: conversation(),
        expected_version: 1,
        text: MessageText::new(text).unwrap(),
    };
    let started = text_service(fixture)
        .begin(&command_context, original.clone())
        .unwrap();
    (command_context, original, started)
}

#[test]
fn conversation_text_started_is_indeterminate_until_terminal_evidence_exists() {
    let fixture = Fixture::new("reconcile-conversation-started");
    fixture.conversation(command(21), "key");
    let command_id = command(22);
    let (command_context, _, _) = begin(&fixture, command_id, "hello");
    let witness = CommandReconciliationWitness::generate_conversation_text(
        conversation(),
        1,
        CanonicalMessageText::new("hello").unwrap(),
    );

    assert_eq!(
        fixture
            .repository
            .reconcile_command(&context(command_id), &witness),
        Ok(CommandReconciliationEvidence::TextGenerationStarted)
    );
    assert_eq!(command_context.command_id, command_id);
}

#[test]
fn completed_text_reconciliation_preserves_typed_messages_and_linkage() {
    let fixture = Fixture::new("reconcile-conversation-completed");
    fixture.conversation(command(23), "key");
    let command_id = command(24);
    let (command_context, original, started) = begin(&fixture, command_id, "hello");
    let witness = CommandReconciliationWitness::generate_conversation_text(
        conversation(),
        1,
        CanonicalMessageText::new("hello").unwrap(),
    );
    text_service(&fixture)
        .finish(
            &command_context,
            FinishConversationTextInput {
                original,
                started: started.clone(),
                completion: ConversationTextCompletion::AssistantText(
                    MessageText::new("world").unwrap(),
                ),
            },
        )
        .unwrap();

    let CommandReconciliationEvidence::Terminal(outcome) = fixture
        .repository
        .reconcile_command(&context(command_id), &witness)
        .unwrap()
    else {
        panic!("expected durable terminal");
    };
    let stream = fixture.store.load_conversation(conversation()).unwrap();
    let user_committed_at = gocode_api::NonNegativeUnixMillis::new(
        stream.events[1]
            .timestamp()
            .as_unix_micros()
            .div_euclid(1_000),
    )
    .unwrap();
    let assistant_committed_at = gocode_api::NonNegativeUnixMillis::new(
        stream.events[2]
            .timestamp()
            .as_unix_micros()
            .div_euclid(1_000),
    )
    .unwrap();
    let expected = AuthoritativeCommandOutcome::conversation_text(
        AuthoritativeTextGenerationOutcome::Completed(gocode_api::ConversationTextResult {
            conversation_id: conversation(),
            taskrun_id: started.taskrun_id,
            attempt_id: started.attempt_id,
            conversation_stream_version: 3,
            taskrun_stream_version: 5,
            user_message: gocode_api::CanonicalConversationMessage {
                message_id: started.user_message_id,
                role: CanonicalMessageRole::User,
                taskrun_id: started.taskrun_id,
                attempt_id: started.attempt_id,
                text: "hello".into(),
                committed_at: user_committed_at,
            },
            assistant_message: gocode_api::CanonicalConversationMessage {
                message_id: started.assistant_message_id,
                role: CanonicalMessageRole::Assistant,
                taskrun_id: started.taskrun_id,
                attempt_id: started.attempt_id,
                text: "world".into(),
                committed_at: assistant_committed_at,
            },
        }),
    );
    assert_eq!(*outcome, expected);
    let conversation = Conversation::replay(&stream.events).unwrap();
    assert_eq!(stream.current_version, 3);
    assert_eq!(conversation.messages().len(), 2);
    assert_eq!(conversation.messages()[0].role, MessageRole::User);
    assert_eq!(
        conversation.messages()[0].message_id,
        started.user_message_id
    );
    assert_eq!(conversation.messages()[1].role, MessageRole::Assistant);
    assert_eq!(
        conversation.messages()[1].message_id,
        started.assistant_message_id
    );
}

#[test]
fn rejected_terminal_preserves_reserved_assistant_identity_without_message() {
    assert_rejected_terminal(
        "reconcile-text-rejected",
        command(25),
        ConversationTextCompletion::Rejected {
            reason: GenerationFailureReason::ProviderOutputRejected,
        },
        TextGenerationPhase::Rejected,
    );
}

#[test]
fn prohibited_input_rejection_is_a_closed_terminal_without_assistant_message() {
    assert_rejected_terminal(
        "reconcile-text-prohibited",
        command(26),
        ConversationTextCompletion::ProhibitedInputRejected {
            reason: GenerationFailureReason::ProviderOutputRejected,
        },
        TextGenerationPhase::ProhibitedInputRejected,
    );
}

fn assert_rejected_terminal(
    name: &str,
    command_id: CommandId,
    completion: ConversationTextCompletion,
    phase: TextGenerationPhase,
) {
    let fixture = Fixture::new(name);
    fixture.conversation(command(27), "key");
    let (command_context, original, started) = begin(&fixture, command_id, "hello");
    let witness = CommandReconciliationWitness::generate_conversation_text(
        conversation(),
        1,
        CanonicalMessageText::new("hello").unwrap(),
    );
    let finished = text_service(&fixture)
        .finish(
            &command_context,
            FinishConversationTextInput {
                original,
                started: started.clone(),
                completion,
            },
        )
        .unwrap();
    assert_eq!(finished.phase, phase);
    assert_eq!(finished.conversation_version, 3);
    assert_eq!(finished.taskrun_version, 5);

    let CommandReconciliationEvidence::Terminal(outcome) = fixture
        .repository
        .reconcile_command(&context(command_id), &witness)
        .unwrap()
    else {
        panic!("expected durable terminal");
    };
    let stream = fixture.store.load_conversation(conversation()).unwrap();
    let user_committed_at = gocode_api::NonNegativeUnixMillis::new(
        stream.events[1]
            .timestamp()
            .as_unix_micros()
            .div_euclid(1_000),
    )
    .unwrap();
    assert_eq!(
        *outcome,
        AuthoritativeCommandOutcome::conversation_text(match phase {
            TextGenerationPhase::Rejected => AuthoritativeTextGenerationOutcome::Rejected {
                conversation_id: conversation(),
                taskrun_id: started.taskrun_id,
                attempt_id: started.attempt_id,
                conversation_stream_version: 3,
                taskrun_stream_version: 5,
                user_message: gocode_api::CanonicalConversationMessage {
                    message_id: started.user_message_id,
                    role: CanonicalMessageRole::User,
                    taskrun_id: started.taskrun_id,
                    attempt_id: started.attempt_id,
                    text: "hello".into(),
                    committed_at: user_committed_at,
                },
                reserved_assistant_message_id: started.assistant_message_id,
                reason: GenerationFailureReason::ProviderOutputRejected,
            },
            TextGenerationPhase::ProhibitedInputRejected => {
                AuthoritativeTextGenerationOutcome::ProhibitedInputRejected {
                    conversation_id: conversation(),
                    taskrun_id: started.taskrun_id,
                    attempt_id: started.attempt_id,
                    conversation_stream_version: 3,
                    taskrun_stream_version: 5,
                    user_message: gocode_api::CanonicalConversationMessage {
                        message_id: started.user_message_id,
                        role: CanonicalMessageRole::User,
                        taskrun_id: started.taskrun_id,
                        attempt_id: started.attempt_id,
                        text: "hello".into(),
                        committed_at: user_committed_at,
                    },
                    reserved_assistant_message_id: started.assistant_message_id,
                    reason: GenerationFailureReason::ProviderOutputRejected,
                }
            }
            _ => panic!("expected rejected terminal phase"),
        })
    );
    let conversation = Conversation::replay(&stream.events).unwrap();
    assert_eq!(conversation.state, ConversationState::Active);
    assert_eq!(conversation.active_generation(), None);
    assert_eq!(conversation.messages().len(), 1);
    assert_eq!(conversation.messages()[0].role, MessageRole::User);
    assert_eq!(
        conversation.messages()[0].message_id,
        started.user_message_id
    );
    assert!(
        conversation
            .messages()
            .iter()
            .all(|message| message.message_id != started.assistant_message_id)
    );
}
