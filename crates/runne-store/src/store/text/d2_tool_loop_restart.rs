use super::*;
use runne_application::ports::{D2ToolLoopRestartEvidence, RejectTextGenerationCommit};
use rusqlite::params;

pub(super) fn terminal_taskrun_head(
    fallback: u64,
    evidence: Option<&D2ToolLoopRestartEvidence>,
) -> u64 {
    evidence.map_or(fallback, |evidence| evidence.expected_taskrun_head)
}

pub(super) fn retire_occupation(
    tx: &rusqlite::Transaction<'_>,
    evidence: &D2ToolLoopRestartEvidence,
    terminal_event: &UncommittedEvent<TaskRunEvent>,
    terminal_version: u64,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let identity = &evidence.assignment;
    let node = uuid::Uuid::parse_str(&identity.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if terminal_event.payload()
        != &(TaskRunEvent::TaskRunFailed {
            reason: "interrupted_by_restart".into(),
        })
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let intent: Option<String> = tx
        .query_row(
            "SELECT dispatch_intent FROM taskrun_assignment_occupations
         WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5
           AND state='active' AND release_event_id IS NULL",
            params![
                identity.taskrun_id.as_bytes(),
                identity.fence.0 as i64,
                identity.attempt_id.as_bytes(),
                node.as_bytes(),
                identity.node_epoch as i64
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if intent.as_deref() != Some("absent") {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let effects: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2)
          OR EXISTS(SELECT 1 FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2)
          OR EXISTS(SELECT 1 FROM taskrun_local_command_attempts WHERE taskrun_id=?1)",
            params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if effects {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    tx.execute(
        "INSERT INTO taskrun_terminal_settlement_receipts
         (taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            identity.taskrun_id.as_bytes(),
            identity.fence.0 as i64,
            identity.attempt_id.as_bytes(),
            node.as_bytes(),
            identity.node_epoch as i64,
            terminal_event.event_id().as_bytes(),
            terminal_version as i64
        ],
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let changed = tx
        .execute(
            "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1
         WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6
           AND state='active' AND dispatch_intent='absent' AND release_event_id IS NULL",
            params![
                terminal_event.event_id().as_bytes(),
                identity.taskrun_id.as_bytes(),
                identity.fence.0 as i64,
                identity.attempt_id.as_bytes(),
                node.as_bytes(),
                identity.node_epoch as i64
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

pub(super) fn verify(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationCommit,
    evidence: D2ToolLoopRestartEvidence,
    started: &TextGenerationReceipt,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    use crate::store::test_support_diagnostics as diagnostics;
    let assignment = &evidence.assignment;
    let node = uuid::Uuid::parse_str(&assignment.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let authority = uuid::Uuid::parse_str(&payload.idempotency_scope.runtime_authority_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if assignment.taskrun_id != started.taskrun_id
        || assignment.attempt_id != started.attempt_id
        || payload.expected_taskrun_version != started.taskrun_version
        || evidence.expected_taskrun_head < started.taskrun_version
        || evidence.recovery_epoch <= assignment.node_epoch
        || node != authority
        || payload.conversation_events[0].payload()
            != &(ConversationEvent::GenerationFailed {
                taskrun_id: started.taskrun_id,
                attempt_id: started.attempt_id,
                reason: runne_domain::conversation::GenerationFailureReason::InterruptedByRestart,
            })
        || payload.taskrun_events[0].payload()
            != &(TaskRunEvent::TaskRunFailed {
                reason: "interrupted_by_restart".into(),
            })
    {
        diagnostics::record("restart.binding");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let now_ms = super::super::position_helpers::current_time_micros()?
        .checked_div(1_000)
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let live: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM execution_nodes WHERE node_id=?1 AND launch_generation=?2 AND expires_at_ms>?3)",
        params![node.as_bytes(), i64::try_from(evidence.recovery_epoch).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?, now_ms],
        |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !live {
        diagnostics::record("restart.live_epoch");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    crate::store::taskrun_claim::verify_assignment_history(tx, assignment)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        tx,
        started.taskrun_id,
        Some(evidence.expected_taskrun_head),
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let task = runne_domain::task_run::TaskRun::replay(&stream.events)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let snapshot = task.snapshot_v1();
    let early_cycle = snapshot.active_cycle().is_some_and(|cycle| {
        matches!(
            cycle.state,
            runne_domain::agent_loop::LoopCycleState::Observing
                | runne_domain::agent_loop::LoopCycleState::Proposing
        ) && cycle.plan_revision_ref.is_none()
            && cycle.expected_proposal_indexes.is_empty()
            && cycle.recorded_outcomes.is_empty()
            && cycle.attempt_id == started.attempt_id
    });
    let expected_head = match snapshot.active_cycle() {
        None => Some(started.taskrun_version),
        Some(cycle)
            if cycle.state == runne_domain::agent_loop::LoopCycleState::Observing
                && cycle.context_manifest_ref.is_none() =>
        {
            started.taskrun_version.checked_add(1)
        }
        Some(cycle)
            if cycle.state == runne_domain::agent_loop::LoopCycleState::Proposing
                && cycle.context_manifest_ref.is_some() =>
        {
            started.taskrun_version.checked_add(2)
        }
        Some(_) => None,
    };
    if task.state() != runne_domain::task_run::TaskRunState::Running {
        diagnostics::record("restart.taskrun_state");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if snapshot.active_attempt() != Some(&started.attempt_id) {
        diagnostics::record("restart.active_attempt");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if snapshot.active_cycle().is_some() && !early_cycle {
        diagnostics::record("restart.active_cycle");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if expected_head != Some(evidence.expected_taskrun_head) {
        diagnostics::record("restart.expected_head");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if task
        .snapshot_v1()
        .input()
        .and_then(|input| input.selected_profile())
        .is_none_or(|profile| profile.profile_id() != "runne-linux-agent-tools-v1")
    {
        diagnostics::record("restart.profile");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let claim: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND node_id=?4 AND node_epoch=?5 AND new_version=?6)",
        params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes(), assignment.fence.0 as i64, node.as_bytes(), assignment.node_epoch as i64, i64::try_from(started.taskrun_version).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?],
        |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !claim {
        diagnostics::record("restart.claim");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let budget_rows: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            params![started.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if budget_rows > 0 {
        let exact: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND node_id=?4 AND node_epoch=?5 AND policy_revision='d2-safe-tool-loop-budget-v1')",
            params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes(), assignment.fence.0 as i64, node.to_string(), assignment.node_epoch as i64],
            |row| row.get(0),
        ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if !exact {
            diagnostics::record("restart.budget");
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    for (table, attempt_column) in [
        ("taskrun_tool_invocations", "attempt_id"),
        ("taskrun_provider_round_bindings", "attempt_id"),
        ("provider_execution_admissions", "execution_attempt_id"),
    ] {
        let query =
            format!("SELECT COUNT(*) FROM {table} WHERE taskrun_id=?1 AND {attempt_column}=?2");
        let count: i64 = tx
            .query_row(
                &query,
                params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if count != 0 {
            diagnostics::record("restart.effect_rows");
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    let dispatch_intent: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3)",
        params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes(), assignment.fence.0 as i64],
        |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if dispatch_intent {
        diagnostics::record("restart.dispatch_intent");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}
