use super::*;
use runne_application::fingerprint::CommandFingerprint;
use rusqlite::params;

#[test]
fn text_only_create_receipt_requires_text_only_scope_witness() {
    let fixture = Fixture::new("reconcile-text-only-create-scope");
    let command_id = command(20);
    let command_context = application_context(command_id, "key");
    ConversationService::new(
        fixture.store.clone(),
        fixture.store.clone(),
        RuntimeAuthorityId("authority".into()),
    )
    .create_from_application(
        &command_context,
        CreateConversationInput {
            conversation_id: conversation(),
            workspace_id: workspace(),
            command_id,
            idempotency_key: command_context.idempotency_key.clone(),
            scope: ConversationContextScope::TextOnly,
        },
    )
    .unwrap();

    let text_only =
        CommandReconciliationWitness::create_text_only_conversation(conversation(), workspace());
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(command_id), &text_only),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));
    let workspace_witness =
        CommandReconciliationWitness::create_conversation(conversation(), workspace());
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&context(command_id), &workspace_witness),
        Err(runne_application::command_reconciliation::CommandReconciliationRepositoryError::Conflict)
    );
}

#[test]
fn workspace_legacy_receipt_reconciles_with_and_without_scope_marker() {
    let fixture = Fixture::new("reconcile-workspace-legacy-receipt");
    let command_id = command(29);
    fixture.conversation(command_id, "key");
    let legacy = CommandFingerprint::for_create_conversation_legacy(&conversation(), &workspace());
    let writer =
        validated_reopen::open_validated_connection(fixture._file.path(), fixture.identity)
            .unwrap();
    writer
        .execute(
            "UPDATE command_receipts SET fingerprint = ?1 WHERE command_id = ?2",
            params![legacy.as_bytes(), command_id.as_bytes()],
        )
        .unwrap();
    drop(writer);

    let witness = CommandReconciliationWitness::create_conversation(conversation(), workspace());
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(command_id), &witness),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));
    let writer =
        validated_reopen::open_validated_connection(fixture._file.path(), fixture.identity)
            .unwrap();
    writer
        .execute(
            "DELETE FROM conversation_context_scope WHERE conversation_id = ?1",
            [conversation().as_bytes()],
        )
        .unwrap();
    drop(writer);
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(command_id), &witness),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));
}
