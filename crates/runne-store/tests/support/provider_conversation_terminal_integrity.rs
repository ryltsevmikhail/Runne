use super::*;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, CommitError, ConversationTextRepository, EventStore, IdGenerator,
    IdempotencyScope, OperationTag, ProviderTerminalCancellationEvidence,
    RejectTextGenerationAfterTerminalCancellationCommit, TextGenerationPhase,
};
use runne_domain::event::{Sensitivity, UncommittedEvent};
use runne_domain::id::AggregateId;
use runne_domain::task_run::TaskRunEvent;
use runne_provider::ProviderTerminalDisposition;
use rusqlite::Connection;

#[test]
fn changed_reserved_assistant_id_is_rejected_before_any_commit() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database = daemon.join("terminal-receipt-integrity.sqlite");
    let authority = RuntimeAuthorityId("terminal-receipt-integrity".into());
    let store = StoreTransaction::open(
        database.to_str().unwrap(),
        authority.clone(),
        available_guard(),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000091".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000092".parse().unwrap();
    validated_reopen::seed_canonical_workspace(&store, "local-owner", workspace_id);
    let create_context = context("018f2e3a-7000-7000-8000-000000000093", "terminal-create");
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let command = context("018f2e3a-7000-7000-8000-000000000094", "terminal-start");
    let text = MessageText::new("terminal integrity prompt").unwrap();
    let service = ConversationTextService::new(
        store.clone(),
        store.clone(),
        authority.clone(),
        available_guard(),
    );
    let started = service
        .begin_text(
            &command,
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: text.clone(),
            },
        )
        .unwrap();

    let conversation = store.load_conversation(conversation_id).unwrap();
    let taskrun = store.load_task_run(started.taskrun_id).unwrap();
    let conversation_event = UncommittedEvent::from_parts(
        store.next_event_ids(1).unwrap().remove(0),
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        conversation.last_event_id,
        command.command_id,
        command.idempotency_key.clone(),
        1,
        command.actor.clone(),
        Sensitivity::Public,
        runne_domain::conversation::ConversationEvent::GenerationFailed {
            taskrun_id: started.taskrun_id,
            attempt_id: started.attempt_id,
            reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
        },
    );
    let taskrun_event = UncommittedEvent::from_parts(
        store.next_event_ids(1).unwrap().remove(0),
        AggregateId::TaskRun(started.taskrun_id),
        AggregateId::TaskRun(started.taskrun_id),
        taskrun.last_event_id,
        command.command_id,
        command.idempotency_key.clone(),
        1,
        command.actor.clone(),
        Sensitivity::Public,
        TaskRunEvent::CancellationCompleted,
    );
    let mut forged_receipt = started.clone();
    forged_receipt.phase = TextGenerationPhase::Rejected;
    forged_receipt.assistant_message_id = runne_domain::id::MessageId::from_bytes([0x91; 16]);
    forged_receipt.conversation_version += 1;
    forged_receipt.taskrun_version += 2;
    let payload = RejectTextGenerationAfterTerminalCancellationCommit {
        command_id: command.command_id,
        idempotency_key: command.idempotency_key.clone(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: authority,
            principal_id: command.principal_id,
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
        },
        command_fingerprint: CommandFingerprint::for_generate_conversation_text(
            &conversation_id,
            1,
            &text,
        ),
        expected_conversation_version: started.conversation_version,
        expected_started_taskrun_version: started.taskrun_version,
        evidence: ProviderTerminalCancellationEvidence {
            dispatch_attempt_id: [0x92; 16],
            disposition: ProviderTerminalDisposition::Completed,
            settlement_digest: [0x93; 32],
            cancellation_taskrun_version: started.taskrun_version + 1,
        },
        conversation_events: vec![conversation_event],
        taskrun_events: vec![taskrun_event],
        receipt: forged_receipt,
    };
    let before = receipt_and_state(&database, command.command_id);
    let mut forged_workspace = payload.clone();
    forged_workspace.receipt.workspace_id = WorkspaceId::from_bytes([0x94; 16]);
    assert!(matches!(
        store.reject_text_generation_after_terminal_cancellation(payload),
        Err(CommitError::StorageFailure(
            runne_application::ports::StorageFailureKind::IntegrityViolation
        ))
    ));
    assert_eq!(receipt_and_state(&database, command.command_id), before);
    assert!(matches!(
        store.reject_text_generation_after_terminal_cancellation(forged_workspace),
        Err(CommitError::StorageFailure(
            runne_application::ports::StorageFailureKind::IntegrityViolation
        ))
    ));
    assert_eq!(receipt_and_state(&database, command.command_id), before);
}

fn receipt_and_state(
    database: &std::path::Path,
    command_id: runne_domain::id::CommandId,
) -> (Vec<u8>, i64, i64, i64) {
    let connection = Connection::open(database).unwrap();
    let receipt: Vec<u8> = connection
        .query_row(
            "SELECT command_outcome FROM command_receipts WHERE command_id=?1",
            [command_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let events = connection
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    let occupations = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_assignment_occupations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let settlements = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    (receipt, events, occupations, settlements)
}
