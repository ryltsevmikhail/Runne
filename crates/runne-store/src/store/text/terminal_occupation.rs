use super::super::parse_helpers::storage_failure;
use super::super::*;
use runne_application::ports::TaskRunAssignmentIdentity;

pub(super) fn retire_terminal_occupation(
    tx: &rusqlite::Transaction<'_>,
    receipt: &TextGenerationReceipt,
    terminal_event: &UncommittedEvent<TaskRunEvent>,
) -> Result<(), CommitError> {
    let claim: Option<(Vec<u8>, i64, i64)> = tx.query_row(
        "SELECT node_id,node_epoch,fence FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2 AND new_version=?3",
        params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes(), receipt.taskrun_version.saturating_sub(1) as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((node, epoch, fence)) = claim else {
        let any_claim: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE taskrun_id=?1)",
                [receipt.taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        return if any_claim {
            Err(storage_failure(StorageFailureKind::IntegrityViolation))
        } else {
            Ok(())
        };
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id: receipt.taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: runne_application::ports::ExecutionNodeId(
            uuid::Uuid::from_slice(&node)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
                .to_string(),
        ),
        node_epoch: u64::try_from(epoch)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        fence: runne_application::ports::TaskRunFence(
            u64::try_from(fence).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        ),
    };
    let intent: Option<String> = tx.query_row(
        "SELECT dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND state='active' AND release_event_id IS NULL",
        params![receipt.taskrun_id.as_bytes(), identity.fence.0 as i64,
            receipt.attempt_id.as_bytes(), uuid::Uuid::parse_str(&identity.node_id.0).unwrap().as_bytes(), identity.node_epoch as i64],
        |row| row.get(0),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let intent = intent.ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if !valid_terminal_for_intent(terminal_event.payload(), &intent) {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if intent == "absent" {
        verify_no_effect_rows(tx, &identity)?;
    }
    tx.execute(
        "INSERT INTO taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![receipt.taskrun_id.as_bytes(), identity.fence.0 as i64,
            receipt.attempt_id.as_bytes(), uuid::Uuid::parse_str(&identity.node_id.0).unwrap().as_bytes(),
            identity.node_epoch as i64, terminal_event.event_id().as_bytes(), receipt.taskrun_version as i64],
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let changed = tx.execute(
        "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6 AND state='active' AND dispatch_intent IN ('present','absent') AND release_event_id IS NULL",
        params![terminal_event.event_id().as_bytes(), receipt.taskrun_id.as_bytes(),
            identity.fence.0 as i64, receipt.attempt_id.as_bytes(),
            uuid::Uuid::parse_str(&identity.node_id.0).unwrap().as_bytes(), identity.node_epoch as i64],
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

pub(super) fn verify_claimed_terminal_before_append(
    tx: &rusqlite::Transaction<'_>,
    receipt: &TextGenerationReceipt,
    expected_started_taskrun_version: u64,
    terminal_event: &UncommittedEvent<TaskRunEvent>,
) -> Result<(), CommitError> {
    let row: Option<(Vec<u8>, i64, i64)> = tx.query_row(
        "SELECT node_id,node_epoch,fence FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2 AND new_version=?3",
        params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes(), expected_started_taskrun_version as i64],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((node, epoch, fence)) = row else {
        let any: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE taskrun_id=?1)",
                [receipt.taskrun_id.as_bytes()],
                |r| r.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        return if any {
            Err(storage_failure(StorageFailureKind::IntegrityViolation))
        } else {
            Ok(())
        };
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id: receipt.taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: runne_application::ports::ExecutionNodeId(
            uuid::Uuid::from_slice(&node)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
                .to_string(),
        ),
        node_epoch: u64::try_from(epoch)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        fence: runne_application::ports::TaskRunFence(
            u64::try_from(fence).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        ),
    };
    crate::store::taskrun_claim::verify_active_assignment(tx, &identity)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let intent: Option<String> = tx.query_row(
        "SELECT dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND state='active' AND release_event_id IS NULL",
        params![receipt.taskrun_id.as_bytes(),identity.fence.0 as i64,receipt.attempt_id.as_bytes(),uuid::Uuid::parse_str(&identity.node_id.0).unwrap().as_bytes(),identity.node_epoch as i64],
        |r| r.get(0),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if intent
        .as_deref()
        .is_some_and(|intent| valid_terminal_for_intent(terminal_event.payload(), intent))
    {
        if intent.as_deref() == Some("absent") {
            verify_no_effect_rows(tx, &identity)?;
        }
        Ok(())
    } else {
        Err(storage_failure(StorageFailureKind::IntegrityViolation))
    }
}

fn verify_no_effect_rows(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
) -> Result<(), CommitError> {
    let present: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2)
          OR EXISTS(SELECT 1 FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2)
          OR EXISTS(SELECT 1 FROM taskrun_local_command_attempts WHERE taskrun_id=?1)",
            params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if present {
        Err(storage_failure(StorageFailureKind::IntegrityViolation))
    } else {
        Ok(())
    }
}

fn valid_terminal_for_intent(event: &TaskRunEvent, intent: &str) -> bool {
    match intent {
        "present" => matches!(
            event,
            TaskRunEvent::TaskRunCompleted { .. }
                | TaskRunEvent::TaskRunFailed { .. }
                | TaskRunEvent::TaskRunCancelled
                | TaskRunEvent::CancellationCompleted
                | TaskRunEvent::Unrecoverable
        ),
        "absent" => {
            matches!(event,
                TaskRunEvent::TaskRunFailed { reason }
                    if matches!(reason.as_str(), "dispatch_not_started" | "provider_execution_rejected" | "interrupted_by_restart")
            ) || matches!(
                event,
                TaskRunEvent::TaskRunCancelled | TaskRunEvent::CancellationCompleted
            )
        }
        _ => false,
    }
}
