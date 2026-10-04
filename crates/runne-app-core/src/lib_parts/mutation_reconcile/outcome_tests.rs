use super::reconciliation_outcome_to_ledger;
use runne_local_store::{
    CanonicalMutationOutcome, GenerationAssistant, GenerationFailureReason, GenerationTerminal,
    NormalizedMutationCommand,
};
use runne_runtime_client::{
    CanonicalId, CommandReconciliationOutcome, ConversationGenerationFailureReason,
    ConversationMessage, ConversationMessageRole, ConversationTextRejection,
};

fn canonical(value: &str) -> CanonicalId {
    CanonicalId::parse(value).unwrap()
}

#[test]
fn accounting_unknown_reconciliation_keeps_its_typed_ledger_reason() {
    let conversation = canonical("018f2e3a-7000-7000-8000-000000000303");
    let task_run = canonical("018f2e3a-7000-7000-8000-000000000304");
    let attempt = canonical("018f2e3a-7000-7000-8000-000000000305");
    let user_message = canonical("018f2e3a-7000-7000-8000-000000000306");
    let reserved_message = canonical("018f2e3a-7000-7000-8000-000000000307");
    let command = NormalizedMutationCommand::GenerateText {
        conversation_id: runne_local_store::BoundedCanonicalId::parse(
            conversation.to_string().as_bytes(),
        )
        .unwrap(),
        expected_version: 1,
        text: "hello".into(),
    };
    let outcome = CommandReconciliationOutcome::ConversationTextRejected(Box::new(
        ConversationTextRejection {
            conversation_id: conversation,
            task_run_id: task_run,
            attempt_id: attempt,
            conversation_stream_version: 3,
            task_run_stream_version: 5,
            user_message: ConversationMessage {
                message_id: user_message,
                role: ConversationMessageRole::User,
                task_run_id: task_run,
                attempt_id: attempt,
                text: "hello".into(),
                committed_at: 1,
            },
            reserved_assistant_message_id: reserved_message,
            reason: ConversationGenerationFailureReason::ProviderAccountingUnknown,
        },
    ));
    let ledger = reconciliation_outcome_to_ledger(&command, &outcome).unwrap();
    assert!(matches!(
        &ledger,
        CanonicalMutationOutcome::Generation {
            terminal: GenerationTerminal::Rejected,
            assistant,
            ..
        } if matches!(
            &**assistant,
            GenerationAssistant::Rejected {
                reason: GenerationFailureReason::ProviderAccountingUnknown,
                ..
            }
        )
    ));
    assert_eq!(
        CanonicalMutationOutcome::decode(&ledger.encode().unwrap()).unwrap(),
        ledger
    );
}

#[test]
fn cancelled_v6_reconciliation_maps_truthfully_into_local_ledger() {
    let conversation = canonical("018f2e3a-7000-7000-8000-000000000303");
    let task_run = canonical("018f2e3a-7000-7000-8000-000000000304");
    let attempt = canonical("018f2e3a-7000-7000-8000-000000000305");
    let user_message = canonical("018f2e3a-7000-7000-8000-000000000306");
    let reserved_message = canonical("018f2e3a-7000-7000-8000-000000000307");
    let command = NormalizedMutationCommand::GenerateText {
        conversation_id: runne_local_store::BoundedCanonicalId::parse(
            conversation.to_string().as_bytes(),
        )
        .unwrap(),
        expected_version: 1,
        text: "hello".into(),
    };
    let outcome = CommandReconciliationOutcome::ConversationTextRejected(Box::new(
        ConversationTextRejection {
            conversation_id: conversation,
            task_run_id: task_run,
            attempt_id: attempt,
            conversation_stream_version: 3,
            task_run_stream_version: 6,
            user_message: ConversationMessage {
                message_id: user_message,
                role: ConversationMessageRole::User,
                task_run_id: task_run,
                attempt_id: attempt,
                text: "hello".into(),
                committed_at: 1,
            },
            reserved_assistant_message_id: reserved_message,
            reason: ConversationGenerationFailureReason::Cancelled,
        },
    ));
    let ledger = reconciliation_outcome_to_ledger(&command, &outcome).unwrap();
    assert!(matches!(
        &ledger,
        CanonicalMutationOutcome::Generation {
            terminal: GenerationTerminal::Rejected,
            task_run_stream_version: 6,
            assistant,
            ..
        } if matches!(
            &**assistant,
            GenerationAssistant::Rejected {
                reason: GenerationFailureReason::Cancelled,
                ..
            }
        )
    ));
    let decoded = CanonicalMutationOutcome::decode(&ledger.encode().unwrap()).unwrap();
    assert_eq!(decoded, ledger);
}
