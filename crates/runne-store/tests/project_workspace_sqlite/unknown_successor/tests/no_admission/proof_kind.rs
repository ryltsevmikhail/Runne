use super::*;

#[test]
fn no_admission_receipt_rejects_a_mismatched_cancel_version_on_replay() {
    let fixture = running_without_provider_admission("no-admission-proof-kind", 0x58);
    let begin_context = context(0x5a, "unknown-successor-generation");
    let started = fixture
        .database
        .store
        .load_text_generation_receipt_by_command(
            begin_context.command_id,
            &begin_context.idempotency_key,
        )
        .unwrap();
    let cancellation_version = request_cancel(&fixture.database, &started);
    close_cancelled_without_admission(
        &fixture.database,
        begin_context.clone(),
        started.clone(),
        "successor fixture request",
        cancellation_version,
    );
    let text = ConversationTextService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        super::super::super::fixture::runtime_authority(),
        guard(),
    );
    let result = text.finish_text(
        &begin_context,
        FinishConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id: started.conversation_id,
                expected_version: started.conversation_version - 1,
                text: MessageText::new("successor fixture request").unwrap(),
            },
            started: started.clone(),
            completion: ConversationTextCompletion::NoProviderAdmissionCancellation {
                evidence: runne_application::ports::ProviderNoAdmissionCancellationEvidence {
                    cancellation_taskrun_version: cancellation_version + 1,
                },
            },
        },
    );
    assert!(result.is_err());
    assert_no_provider_effects(&fixture.database, started.taskrun_id, started.attempt_id);
}
