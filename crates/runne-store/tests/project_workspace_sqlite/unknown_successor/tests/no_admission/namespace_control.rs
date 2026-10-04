use super::*;
use runne_application::ports::{IdGenerationError, IdGenerator};
use runne_domain::id::{AttemptId, CheckpointId, CycleId, EventId, MessageId, TaskRunId};

struct DispatchAliasedIds {
    store: runne_store::store::StoreTransaction,
    attempt_id: AttemptId,
}

impl IdGenerator for DispatchAliasedIds {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        self.store.next_taskrun_id()
    }

    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
        self.store.next_conversation_id()
    }

    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok(self.attempt_id)
    }

    fn next_message_id(&self) -> Result<MessageId, IdGenerationError> {
        self.store.next_message_id()
    }

    fn next_cycle_id(&self) -> Result<CycleId, IdGenerationError> {
        self.store.next_cycle_id()
    }

    fn next_checkpoint_id(&self) -> Result<CheckpointId, IdGenerationError> {
        self.store.next_checkpoint_id()
    }

    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        self.store.next_event_ids(count)
    }
}

#[test]
fn unrelated_dispatch_with_matching_attempt_bytes_does_not_block_no_admission() {
    let unrelated = running_without_provider_admission("no-admission-unrelated-dispatch", 0x31);
    let foreign_start = unrelated
        .database
        .store
        .load_text_generation_receipt_by_command(
            command(0x33),
            &key("unknown-successor-generation"),
        )
        .unwrap();
    let expected_dispatch_bytes = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    assert!(
        unrelated
            .execution
            .arm_next_dispatch_attempt_id_for_test([0; 16])
            .is_err()
    );
    unrelated
        .execution
        .arm_next_dispatch_attempt_id_for_test(expected_dispatch_bytes)
        .unwrap();
    let mut overwritten = expected_dispatch_bytes;
    overwritten[15] = 1;
    assert!(
        unrelated
            .execution
            .arm_next_dispatch_attempt_id_for_test(overwritten)
            .is_err()
    );
    super::super::super::fixture::dispatch_unknown(
        &unrelated.database,
        &unrelated.credentials,
        &unrelated.execution,
        &unrelated.launch,
        &unrelated.claim_identity,
        foreign_start.conversation_id,
    );
    let stored_dispatch_bytes: Vec<u8> = unrelated
        .database
        .connection()
        .query_row(
            "SELECT dispatch_attempt_id FROM provider_execution_admissions
             WHERE taskrun_id=?1 AND execution_attempt_id=?2",
            rusqlite::params![
                unrelated.taskrun_id.as_bytes(),
                unrelated.claim_identity.attempt_id.as_bytes()
            ],
            |row| row.get(0),
        )
        .unwrap();
    let dispatch_bytes: [u8; 16] = stored_dispatch_bytes.try_into().unwrap();
    assert_eq!(dispatch_bytes, expected_dispatch_bytes);
    let aliased_attempt = AttemptId::from_bytes(dispatch_bytes);
    let conversation_id = ConversationId::from_bytes(command(0xc1).into_bytes());
    ConversationService::new(
        unrelated.database.store.clone(),
        unrelated.database.store.clone(),
        super::super::super::fixture::runtime_authority(),
    )
    .create_from_application(
        &context(0xc1, "no-admission-namespace-conversation"),
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            command_id: command(0xc1),
            idempotency_key: key("no-admission-namespace-conversation"),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let text = ConversationTextService::new(
        unrelated.database.store.clone(),
        DispatchAliasedIds {
            store: unrelated.database.store.clone(),
            attempt_id: aliased_attempt,
        },
        super::super::super::fixture::runtime_authority(),
        guard(),
    );
    let begin_context = context(0xc2, "no-admission-namespace-text");
    let started = text
        .begin_text(
            &begin_context,
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("separate local request").unwrap(),
            },
        )
        .unwrap();
    assert_eq!(started.attempt_id, aliased_attempt);
    let linked_elsewhere: i64 = unrelated
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM provider_execution_admissions
             WHERE dispatch_attempt_id=?1 AND taskrun_id<>?2",
            rusqlite::params![aliased_attempt.as_bytes(), started.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(linked_elsewhere, 1);
    let target_owned_admissions: i64 = unrelated
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM provider_execution_admissions
             WHERE taskrun_id=?1 AND execution_attempt_id=?2",
            rusqlite::params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        target_owned_admissions, 0,
        "the matching bytes identify another TaskRun's dispatch ID, not an admission here"
    );

    let cancellation_version = request_cancel(&unrelated.database, &started);
    close_cancelled_without_admission(
        &unrelated.database,
        begin_context,
        started.clone(),
        "separate local request",
        cancellation_version,
    );
    let reopened = crate::validated_reopen::reopen_store(
        unrelated.database.file.path(),
        unrelated.database.identity,
        super::super::super::fixture::runtime_authority(),
        guard(),
    )
    .unwrap();
    assert!(reopened.load_task_run(started.taskrun_id).is_ok());
}

#[test]
fn linked_provider_admission_rejects_no_admission_closure() {
    let fixture = running("no-admission-linked-control", 0x51);
    let begin_context = context(0x53, "unknown-successor-generation");
    let started = fixture
        .database
        .store
        .load_text_generation_receipt_by_command(
            begin_context.command_id,
            &begin_context.idempotency_key,
        )
        .unwrap();
    let cancellation_version = request_cancel(&fixture.database, &started);
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
                    cancellation_taskrun_version: cancellation_version,
                },
            },
        },
    );
    assert!(result.is_err());
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(
            &fixture
                .database
                .store
                .load_task_run(started.taskrun_id)
                .unwrap()
                .events
        )
        .unwrap()
        .state(),
        runne_domain::task_run::TaskRunState::Cancelling
    );
}
