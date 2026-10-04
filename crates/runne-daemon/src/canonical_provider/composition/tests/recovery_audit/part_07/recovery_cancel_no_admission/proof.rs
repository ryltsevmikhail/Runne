use super::CancelledNoAdmission;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{ConversationRepository, EventStore};
use runne_domain::id::{AttemptId, TaskRunId};
use runne_domain::task_run::{TaskRun, TaskRunState};
use rusqlite::Connection;

pub(in super::super) struct ClosedNoAdmissionSnapshot {
    taskrun_events: Vec<(Vec<u8>, u64, Vec<u8>)>,
    taskrun_version: u64,
    conversation_events: Vec<(Vec<u8>, u64, Vec<u8>)>,
    conversation_version: u64,
    receipt: runne_application::ports::TextGenerationReceipt,
    provider_counts: Vec<i64>,
}

impl CancelledNoAdmission {
    pub(in super::super) fn tasks(
        &self,
    ) -> std::sync::Arc<
        runne_application::service::TaskRunService<
            runne_store::store::StoreTransaction,
            runne_store::store::StoreTransaction,
            runne_store::store::StoreTransaction,
        >,
    > {
        self.tasks_for(&self.harness.store)
    }

    pub(in super::super) fn tasks_for(
        &self,
        store: &runne_store::store::StoreTransaction,
    ) -> std::sync::Arc<
        runne_application::service::TaskRunService<
            runne_store::store::StoreTransaction,
            runne_store::store::StoreTransaction,
            runne_store::store::StoreTransaction,
        >,
    > {
        std::sync::Arc::new(runne_application::service::TaskRunService::new(
            store.clone(),
            store.clone(),
            store.clone(),
            self.authority.clone(),
        ))
    }

    pub(in super::super) fn reopen_store(&self) -> runne_store::store::StoreTransaction {
        runne_store::store::StoreTransaction::open_with_connections(
            &self.harness.db_path,
            self.harness.writer_connection(),
            self.harness.query_connection(),
            self.authority.clone(),
            self.harness.prohibited(),
        )
        .unwrap()
    }

    pub(in super::super) fn reopened_text(
        &self,
        store: &runne_store::store::StoreTransaction,
    ) -> std::sync::Arc<dyn ConversationTextCommandService> {
        std::sync::Arc::new(ConversationTextService::new(
            store.clone(),
            store.clone(),
            self.authority.clone(),
            self.harness.prohibited(),
        ))
    }

    pub(in super::super) fn assert_no_provider_effects(&self) {
        assert_eq!(
            attempt_effect_counts(
                &self.harness.query_connection(),
                self.taskrun_id,
                self.started.attempt_id,
            ),
            (0, 0, 0, 0, 0)
        );
    }

    pub(in super::super) fn assert_closed(&self, before: &[i64]) {
        let taskrun = self.harness.store.load_task_run(self.taskrun_id).unwrap();
        assert_eq!(
            TaskRun::replay(&taskrun.events).unwrap().state(),
            TaskRunState::Cancelled
        );
        let conversation = self
            .harness
            .store
            .load_conversation(self.conversation_id)
            .unwrap();
        assert!(conversation.events.iter().any(|event| matches!(
                event.payload(),
                runne_domain::conversation::ConversationEvent::GenerationFailed {
                    taskrun_id,
                    attempt_id,
        reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
                } if *taskrun_id == self.taskrun_id && *attempt_id == self.started.attempt_id
            )));
        assert!(!conversation.events.iter().any(|event| matches!(
            event.payload(),
            runne_domain::conversation::ConversationEvent::AssistantMessageAppended { .. }
        )));
        let receipt = self
            .harness
            .store
            .load_text_generation_receipt_by_command(
                self.begin_context.command_id,
                &self.begin_context.idempotency_key,
            )
            .unwrap();
        assert_eq!(
            receipt.phase,
            runne_application::ports::TextGenerationPhase::Rejected
        );
        assert_eq!(receipt.attempt_id, self.started.attempt_id);
        assert_eq!(
            provider_effect_counts(&self.harness.query_connection()),
            before
        );
        self.assert_no_provider_effects();
    }

    pub(in super::super) fn closed_snapshot(&self) -> ClosedNoAdmissionSnapshot {
        let taskrun = self.harness.store.load_task_run(self.taskrun_id).unwrap();
        let conversation = self
            .harness
            .store
            .load_conversation(self.conversation_id)
            .unwrap();
        let receipt = self
            .harness
            .store
            .load_text_generation_receipt_by_command(
                self.begin_context.command_id,
                &self.begin_context.idempotency_key,
            )
            .unwrap();
        ClosedNoAdmissionSnapshot {
            taskrun_events: taskrun.events.iter().map(event_identity).collect(),
            taskrun_version: taskrun.current_version,
            conversation_events: conversation.events.iter().map(event_identity).collect(),
            conversation_version: conversation.current_version,
            receipt,
            provider_counts: provider_effect_counts(&self.harness.query_connection()),
        }
    }

    pub(in super::super) fn assert_reopened_unchanged(
        &self,
        reopened: &runne_store::store::StoreTransaction,
        closed: &ClosedNoAdmissionSnapshot,
    ) {
        let taskrun = reopened.load_task_run(self.taskrun_id).unwrap();
        assert_eq!(taskrun.current_version, closed.taskrun_version);
        assert_eq!(
            taskrun
                .events
                .iter()
                .map(event_identity)
                .collect::<Vec<_>>(),
            closed.taskrun_events
        );
        let conversation = reopened.load_conversation(self.conversation_id).unwrap();
        assert_eq!(conversation.current_version, closed.conversation_version);
        assert_eq!(
            conversation
                .events
                .iter()
                .map(event_identity)
                .collect::<Vec<_>>(),
            closed.conversation_events
        );
        assert_eq!(
            reopened
                .load_text_generation_receipt_by_command(
                    self.begin_context.command_id,
                    &self.begin_context.idempotency_key,
                )
                .unwrap(),
            closed.receipt
        );
        assert_eq!(
            provider_effect_counts(&self.harness.query_connection()),
            closed.provider_counts
        );
        self.assert_no_provider_effects();
    }
}

fn event_identity<E>(event: &runne_domain::event::EventEnvelope<E>) -> (Vec<u8>, u64, Vec<u8>) {
    (
        event.event_id().as_bytes().to_vec(),
        event.sequence(),
        event.integrity_digest().as_bytes().to_vec(),
    )
}

pub(in super::super) fn provider_effect_counts(connection: &Connection) -> Vec<i64> {
    [
        "provider_execution_admissions",
        "provider_dispatch_attempts",
        "provider_budget_reservations",
        "provider_remote_request_intents",
        "provider_remote_terminal_artifacts",
        "provider_remote_terminal_applications",
        "provider_stream_journal",
        "provider_accounting_settlements",
        "provider_terminal_outbox",
        "provider_encryption_nonces",
        "taskrun_provider_bindings",
        "taskrun_local_command_attempts",
    ]
    .into_iter()
    .map(|table| {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    })
    .collect()
}

fn attempt_effect_counts(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) -> (i64, i64, i64, i64, i64) {
    connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM provider_execution_admissions WHERE taskrun_id=?1 AND execution_attempt_id=?2),
                (SELECT COUNT(*) FROM provider_remote_request_intents WHERE taskrun_id=?1 AND taskrun_attempt_id=?2),
                (SELECT COUNT(*) FROM provider_remote_terminal_artifacts WHERE taskrun_id=?1 AND taskrun_attempt_id=?2),
                (SELECT COUNT(*) FROM provider_remote_terminal_applications WHERE taskrun_id=?1 AND taskrun_attempt_id=?2),
                (SELECT COUNT(*) FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND (attempt_id IS NULL OR attempt_id=?2))",
            rusqlite::params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap()
}
