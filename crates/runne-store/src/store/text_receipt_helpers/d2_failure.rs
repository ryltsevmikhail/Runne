use super::*;
use crate::store::taskrun_tool_invocation::budget_policy::is_tool_profile;
use runne_application::ports::D2ToolLoopCancellationEvidence;
use runne_domain::{agent_loop::LoopDisposition, task_run::TaskRun};

pub(crate) fn validate_d2_failed_receipt(
    connection: &Connection,
    command_id: CommandId,
    idempotency_key: &runne_domain::id::IdempotencyKey,
    scope: &IdempotencyScope,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    if receipt.phase != TextGenerationPhase::Rejected
        || receipt.conversation_version < 2
        || receipt.taskrun_version < 1
        || !matches!(scope.aggregate_scope,
            AggregateScope::ExistingConversation { conversation_id }
                if conversation_id == receipt.conversation_id)
    {
        return Ok(false);
    }
    let stream = super::super::taskrun_claim::stream_validate::verify_stream(
        connection,
        receipt.taskrun_id,
        Some(receipt.taskrun_version),
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let task = TaskRun::replay(&stream.events)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if task.state() != TaskRunState::Failed {
        return Ok(false);
    }
    if task
        .snapshot_v1()
        .input()
        .and_then(|input| input.selected_profile())
        .is_none_or(|profile| !is_tool_profile(profile.profile_id()))
    {
        return Ok(false);
    }
    let restart = stream.events.last().is_some_and(|event| {
        matches!(
            event.payload(),
            TaskRunEvent::TaskRunFailed { reason } if reason == "interrupted_by_restart"
        )
    });
    let budget_table: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='taskrun_tool_budgets')",
        [], |row| row.get(0),
    ).map_err(map_commit_read_error)?;
    if !budget_table {
        return Ok(false);
    }
    let budget_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            params![receipt.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(map_commit_read_error)?;
    let budget: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2 AND policy_revision IN ('d2-safe-tool-loop-budget-v1','coding-tool-loop-budget-v1'))",
        params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()], |row| row.get(0),
    ).map_err(map_commit_read_error)?;
    let invocation_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2",
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(map_commit_read_error)?;
    let expected_taskrun_reason = if restart {
        "interrupted_by_restart"
    } else if invocation_count == 0 {
        "provider_execution_rejected"
    } else {
        "D2 tool approval or effect did not complete safely"
    };
    let d2_failures = stream
        .events
        .iter()
        .filter_map(|event| match event.payload() {
            TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition: LoopDisposition::Fail { reason, .. },
            } if *attempt_id == receipt.attempt_id && reason == expected_taskrun_reason => {
                Some(*cycle_id)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let claim: Option<(Vec<u8>, i64, i64, i64)> = connection
        .query_row(
            "SELECT node_id,node_epoch,new_version,fence FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2",
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(map_commit_read_error)?;
    let no_cycle_restart = restart
        && d2_failures.is_empty()
        && claim.as_ref().is_some_and(|(_, _, claim_version, _)| {
            super::d2_restart_shape::valid_retained_early_cycle(
                task.snapshot_v1().active_cycle(),
                *claim_version,
                receipt.taskrun_version,
                receipt.attempt_id,
            )
        })
        && invocation_count == 0;
    if (d2_failures.len() != 1 && !no_cycle_restart)
        || (budget_rows > 0 && !budget)
        || (budget_rows == 0 && invocation_count != 0)
        || !matches!(stream.events.last().map(|event| event.payload()),
            Some(TaskRunEvent::TaskRunFailed { reason })
                if reason == expected_taskrun_reason)
    {
        return Ok(false);
    }
    let terminal_event = stream
        .events
        .last()
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let terminal_id = terminal_event.event_id();
    let node: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM taskrun_assignments a
                JOIN taskrun_assignment_occupations o
                  ON o.taskrun_id=a.taskrun_id AND o.fence=a.fence
                JOIN taskrun_terminal_settlement_receipts s
                  ON s.taskrun_id=a.taskrun_id AND s.fence=a.fence
                 AND s.attempt_id=a.attempt_id AND s.node_id=a.node_id AND s.node_epoch=a.node_epoch
                WHERE a.taskrun_id=?1 AND a.attempt_id=?2
                  AND a.fence=(SELECT MAX(latest.fence) FROM taskrun_assignments latest WHERE latest.taskrun_id=a.taskrun_id)
                  AND o.state='released' AND o.release_event_id=?3
                  AND s.terminal_event_id=?3 AND s.terminal_version=?4
            )",
            params![
                receipt.taskrun_id.as_bytes(),
                receipt.attempt_id.as_bytes(),
                terminal_id.as_bytes(),
                i64::try_from(receipt.taskrun_version)
                    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
            ],
            |row| row.get(0),
        )
        .map_err(map_commit_read_error)?;
    if !node {
        return Ok(false);
    }
    let Some((claim_node, claim_epoch, claim_version, claim_fence)) = claim else {
        return Ok(false);
    };
    let node_bytes: [u8; 16] = claim_node
        .as_slice()
        .try_into()
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if budget_rows > 0 {
        crate::store::taskrun_tool_invocation::budget_policy::verify_origin_policy(
            connection,
            receipt.taskrun_id,
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let exact_budget: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2
               AND fence=?3 AND node_id=?4 AND node_epoch=?5
               AND policy_revision IN ('d2-safe-tool-loop-budget-v1','coding-tool-loop-budget-v1'))",
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes(), claim_fence,
                uuid::Uuid::from_slice(&node_bytes).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?.to_string(), claim_epoch],
            |row| row.get(0),
        ).map_err(map_commit_read_error)?;
        if !exact_budget {
            return Ok(false);
        }
    }
    crate::store::verify_d2_cancelled_provider_rounds(
        connection,
        receipt.taskrun_id,
        receipt.attempt_id,
        D2ToolLoopCancellationEvidence {
            node_id: node_bytes,
            node_epoch: u64::try_from(claim_epoch)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
            fence: u64::try_from(claim_fence)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
            cancellation_taskrun_version: receipt.taskrun_version,
        },
        u64::try_from(claim_version)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
        receipt.taskrun_version,
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if let Some(cycle_id) = d2_failures.first() {
        let claim_node_id = uuid::Uuid::from_slice(&node_bytes)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?
            .to_string();
        let (total, valid, results): (i64, i64, i64) = connection
            .query_row(
                "SELECT COUNT(*), SUM(CASE WHEN
                (state='result' AND result_truncated=0 AND local_stop_state=2
                 AND managed_area_identity IS NOT NULL
                 AND empty_proof_identity=managed_area_identity)
                OR (state IN ('proposed','approved','denied') AND release_started=0
                    AND local_stop_state=0 AND managed_area_identity IS NULL
                    AND empty_proof_identity IS NULL)
                OR (state IN ('uncertain','audit_only') AND local_stop_state=2
                    AND managed_area_identity IS NOT NULL
                    AND empty_proof_identity=managed_area_identity)
                OR (state='claimed' AND claim_fence=?4 AND claim_node_id=?5
                    AND claim_node_epoch=?6 AND release_started=0 AND continuation_started=0
                    AND local_stop_state=0 AND managed_area_identity IS NULL
                    AND empty_proof_identity IS NULL AND result_digest IS NULL
                    AND receipt_nonce IS NULL)
                THEN 1 ELSE 0 END)
                ,SUM(CASE WHEN state='result' AND result_truncated=0 AND local_stop_state=2
                    AND managed_area_identity IS NOT NULL
                    AND empty_proof_identity=managed_area_identity THEN 1 ELSE 0 END)
             FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3",
                params![
                    receipt.taskrun_id.as_bytes(),
                    receipt.attempt_id.as_bytes(),
                    cycle_id.as_bytes(),
                    claim_fence,
                    claim_node_id,
                    claim_epoch,
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                        row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    ))
                },
            )
            .map_err(map_commit_read_error)?;
        if total != valid || (restart && results == 0 && total != 0) {
            return Ok(false);
        }
    } else if invocation_count != 0 {
        return Ok(false);
    }
    let conversation = crate::store::conversation::load_conversation_from_connection(
        connection,
        receipt.conversation_id,
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if conversation.current_version < receipt.conversation_version {
        return Ok(false);
    }
    let user_index = usize::try_from(receipt.conversation_version - 2)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let failure_index = usize::try_from(receipt.conversation_version - 1)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let (Some(user), Some(failure)) = (
        conversation.events.get(user_index),
        conversation.events.get(failure_index),
    ) else {
        return Ok(false);
    };
    let user_matches = matches!(user.payload(),
        ConversationEvent::UserMessageAppended { message_id, taskrun_id, attempt_id, .. }
            if *message_id == receipt.user_message_id
                && *taskrun_id == receipt.taskrun_id
                && *attempt_id == receipt.attempt_id);
    let expected_generation_reason = if restart {
        runne_domain::conversation::GenerationFailureReason::InterruptedByRestart
    } else {
        runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected
    };
    let failure_matches = matches!(failure.payload(),
        ConversationEvent::GenerationFailed { taskrun_id, attempt_id, reason }
            if *taskrun_id == receipt.taskrun_id
                && *attempt_id == receipt.attempt_id
                && *reason == expected_generation_reason);
    let prefix_len = usize::try_from(receipt.conversation_version)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let domain_valid = conversation
        .events
        .get(..prefix_len)
        .is_some_and(|events| runne_domain::conversation::Conversation::replay(events).is_ok());
    Ok(user_matches
        && failure_matches
        && domain_valid
        && user.sequence() == receipt.conversation_version - 1
        && failure.sequence() == receipt.conversation_version
        && user.command_id() == &command_id
        && failure.command_id() == &command_id
        && user.idempotency_key() == idempotency_key
        && failure.idempotency_key() == idempotency_key
        && user.actor() == failure.actor()
        && failure.causation_id().copied() == Some(*user.event_id())
        && user.aggregate_id() == &AggregateId::Conversation(receipt.conversation_id)
        && failure.aggregate_id() == &AggregateId::Conversation(receipt.conversation_id)
        && user.sensitivity() == &user.payload().sensitivity()
        && failure.sensitivity() == &failure.payload().sensitivity())
}
