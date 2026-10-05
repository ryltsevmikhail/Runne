use super::*;
use runne_domain::{
    agent_loop::LoopDisposition,
    id::{AttemptId, CycleId, IntegrityDigest},
    task_run::TaskRunEvent,
    verification::PlanEvaluationRef,
};

impl CompletionRow {
    pub(super) fn completed_replay_matches(
        &self,
        tx: &rusqlite::Transaction<'_>,
        input: &D2ToolLoopCompletionV1,
        message_id: MessageId,
        receipt_digest: IntegrityDigest,
    ) -> Result<bool, CommitError> {
        use crate::store::parse_helpers::storage_failure;
        if !self.matches(input, message_id, receipt_digest) {
            return Ok(false);
        }
        let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
            tx,
            input.taskrun_id,
            Some(input.expected_taskrun_head),
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let task = TaskRun::replay(&stream.events)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let exact_cycle = stream.events.iter().any(|event| {
            exact_completion_event(
                event.payload(),
                input.cycle_id,
                input.attempt_id,
                &input.evaluation_ref,
            )
        });
        let success = stream.events.last().is_some_and(|event| {
            matches!(
                event.payload(),
                TaskRunEvent::TaskRunCompleted {
                    result: runne_domain::command::TerminalResult::Success
                }
            )
        });
        if !exact_cycle || !success || task.state() != TaskRunState::Succeeded {
            return Ok(false);
        }
        let conversation = crate::store::conversation::load_conversation_from_connection(
            tx,
            input.conversation_id,
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if conversation.current_version != input.completed_receipt.conversation_version {
            return Ok(false);
        }
        let expected_text = match input.conversation_event.payload() {
            ConversationEvent::AssistantMessageAppended {
                message_id: expected_id,
                taskrun_id,
                attempt_id,
                text,
            } if *expected_id == message_id
                && *taskrun_id == input.taskrun_id
                && *attempt_id == input.attempt_id =>
            {
                text.as_str()
            }
            _ => return Ok(false),
        };
        let mut messages = conversation.events.iter().filter(|event| {
            matches!(
                event.payload(),
                ConversationEvent::AssistantMessageAppended {
                    message_id: stored_id,
                    taskrun_id,
                    attempt_id,
                    text,
                } if *stored_id == message_id
                    && *taskrun_id == input.taskrun_id
                    && *attempt_id == input.attempt_id
                    && text.as_str() == expected_text
            )
        });
        if messages.next().is_none() || messages.next().is_some() {
            return Ok(false);
        }
        let outbox: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_terminal_outbox o
         JOIN provider_terminal_application_kinds k USING(dispatch_attempt_id,outbox_id)
         JOIN provider_execution_admissions a USING(dispatch_attempt_id)
         WHERE o.dispatch_attempt_id=?1 AND o.outbox_id=?2 AND o.terminal_sequence=?3
           AND o.settlement_digest=?4 AND o.state=2 AND o.receipt_digest=?5
           AND o.plaintext_digest=?6 AND o.plaintext_len=?7 AND k.application_kind=2
           AND a.taskrun_id=?8 AND a.execution_attempt_id=?9 AND a.conversation_id=?10
           AND a.principal_id=?11)",
                params![
                    input.terminal_attempt_id.as_slice(),
                    input.terminal_outbox_id.as_slice(),
                    i64::try_from(input.terminal_sequence)
                        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
                    input.settlement_digest.as_bytes(),
                    receipt_digest.as_bytes(),
                    input.assistant_text_digest.as_bytes(),
                    i64::try_from(input.assistant_text_length)
                        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
                    input.taskrun_id.as_bytes(),
                    input.attempt_id.as_bytes(),
                    input.conversation_id.as_bytes(),
                    input.idempotency_scope.principal_id.0,
                ],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(outbox)
    }
}

fn exact_completion_event(
    event: &TaskRunEvent,
    expected_cycle: CycleId,
    expected_attempt: AttemptId,
    expected_ref: &PlanEvaluationRef,
) -> bool {
    matches!(event,
        TaskRunEvent::LoopCycleCompleted {
            cycle_id,
            attempt_id,
            disposition: LoopDisposition::Complete { plan_evaluation_ref },
        } if *cycle_id == expected_cycle
            && *attempt_id == expected_attempt
            && plan_evaluation_ref == expected_ref
    )
}

impl StoreTransaction {
    /// Confirms that a duplicate caller supplied the exact immutable D2 linkage.
    pub fn validate_d2_tool_loop_completion_replay(
        &self,
        binding: &crate::store::D2ToolLoopCompletionReplayBinding,
    ) -> Result<bool, CommitError> {
        use crate::store::parse_helpers::storage_failure;
        let mut reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = reader
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let row = completion_row(&tx, binding.command_id)?;
        let digest = receipt_digest(&binding.completed_receipt)?;
        let exact_row = row
            .as_ref()
            .is_some_and(|row| row.matches_replay(binding, digest));
        let verified = crate::store::taskrun_claim::stream_validate::verify_stream(
            &tx,
            binding.taskrun_id,
            Some(binding.taskrun_head),
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let exact_evaluation = verified.events.iter().any(|event| {
            matches!(event.payload(), runne_domain::task_run::TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition: LoopDisposition::Complete { plan_evaluation_ref },
            } if *cycle_id == binding.cycle_id
                && *attempt_id == binding.attempt_id
                && plan_evaluation_ref == &binding.evaluation_ref)
        });
        let text_length: Option<i64> = tx
            .query_row(
                "SELECT o.plaintext_len FROM provider_terminal_outbox o
                 JOIN d2_tool_loop_completions c ON c.terminal_outbox_id=o.outbox_id
                 WHERE c.command_id=?1",
                [binding.command_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let exact = exact_row
            && exact_evaluation
            && i64::try_from(binding.assistant_text_length).ok() == text_length;
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        Ok(exact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_domain::{
        id::{PlanEvaluationId, PlanId, TaskRunId},
        verification::PlanEvaluationResult,
    };

    #[test]
    fn replay_rejects_evaluation_ref_with_same_digest_but_changed_fields() {
        let taskrun = TaskRunId::from_bytes([1; 16]);
        let cycle = CycleId::from_bytes([2; 16]);
        let attempt = AttemptId::from_bytes([3; 16]);
        let evaluation_ref = PlanEvaluationRef {
            evaluation_id: PlanEvaluationId::from_bytes([4; 16]),
            taskrun_id: taskrun,
            plan_id: PlanId::from_bytes([5; 16]),
            plan_revision: 7,
            evaluated_stream_head: 9,
            result: PlanEvaluationResult::Passed,
            gate_definitions_digest: IntegrityDigest::from_bytes([6; 32]),
            evidence_set_digest: IntegrityDigest::from_bytes([7; 32]),
            evaluation_digest: IntegrityDigest::from_bytes([8; 32]),
        };
        let event = TaskRunEvent::LoopCycleCompleted {
            cycle_id: cycle,
            attempt_id: attempt,
            disposition: LoopDisposition::Complete {
                plan_evaluation_ref: evaluation_ref.clone(),
            },
        };
        assert!(exact_completion_event(
            &event,
            cycle,
            attempt,
            &evaluation_ref
        ));
        let mut forged = evaluation_ref;
        forged.evaluated_stream_head += 1;
        assert_eq!(
            forged.evaluation_digest,
            IntegrityDigest::from_bytes([8; 32])
        );
        assert!(!exact_completion_event(&event, cycle, attempt, &forged));
    }
}
