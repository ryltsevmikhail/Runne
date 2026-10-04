use super::super::*;

type ClaimAssignmentReceiptRow = (Vec<u8>, i64, i64, i64, Vec<u8>, Vec<u8>);
type TerminalSettlementOccupationRow = (Vec<u8>, i64, String, Option<Vec<u8>>);

pub(super) fn no_provider_rows(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    // DispatchAttemptId is a separate identity space. Prove absence through
    // TaskRun-keyed admissions, dispatch intents, remote requests, and local
    // attempt records; an unrelated orphan dispatch with equal bytes is not
    // evidence about this execution attempt.
    connection
        .query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM provider_execution_admissions
                    WHERE taskrun_id=?1 AND execution_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_provider_bindings
                    WHERE taskrun_id=?1 AND attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents
                    WHERE taskrun_id=?1 AND attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_request_intents
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_response_bindings
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_settlements
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_artifact_cancel_closures
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_operation_proofs
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_applications
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_audit_receipts
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_provider_cancel_fences
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_local_command_attempts
                    WHERE taskrun_id=?1 AND (attempt_id IS NULL OR attempt_id=?2))
                AND NOT EXISTS(SELECT 1 FROM taskrun_local_command_stop_receipts
                    WHERE taskrun_id=?1 AND attempt_id=?2)",
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

pub(super) fn validate(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    events: &[runne_domain::event::EventEnvelope<TaskRunEvent>],
    started_version: u64,
) -> Result<(), CommitError> {
    let counts: (i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1)",
            [receipt.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if counts == (0, 0, 0) {
        return validate_direct_origin(connection, receipt, events, started_version);
    }
    if counts != (1, 1, 1) {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    validate_claimed_origin(connection, receipt, started_version)
}

fn validate_direct_origin(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    events: &[runne_domain::event::EventEnvelope<TaskRunEvent>],
    started_version: u64,
) -> Result<(), CommitError> {
    let claims: i64 = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1)
                  +(SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1)
                  +(SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1)",
            [receipt.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if claims != 0 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let expected_origin = [
        TaskRunEvent::TaskRunCreated,
        TaskRunEvent::TaskRunQueued,
        TaskRunEvent::TaskRunAdmitted,
        TaskRunEvent::AttemptStarted {
            attempt_id: receipt.attempt_id,
        },
    ];
    if events
        .iter()
        .take(
            usize::try_from(started_version)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        )
        .map(|event| event.payload())
        .eq(expected_origin.iter())
    {
        Ok(())
    } else {
        Err(storage_failure(StorageFailureKind::IntegrityViolation))
    }
}

fn validate_claimed_origin(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    started_version: u64,
) -> Result<(), CommitError> {
    let row: Option<ClaimAssignmentReceiptRow> = connection
        .query_row(
            "SELECT c.node_id,c.node_epoch,c.fence,c.new_version,c.admitted_event_id,c.started_event_id
             FROM taskrun_claim_receipts c JOIN taskrun_assignments a ON a.taskrun_id=c.taskrun_id
               AND a.fence=c.fence AND a.attempt_id=c.attempt_id AND a.node_id=c.node_id
               AND a.node_epoch=c.node_epoch AND a.command_id=c.command_id
               AND a.admitted_event_id=c.admitted_event_id AND a.started_event_id=c.started_event_id
             WHERE c.taskrun_id=?1 AND c.attempt_id=?2",
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((node, epoch, fence, claim_version, admitted, started)) = row else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id: receipt.taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: runne_application::ports::ExecutionNodeId(
            uuid::Uuid::from_bytes(
                node.as_slice()
                    .try_into()
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            )
            .to_string(),
        ),
        node_epoch: u64::try_from(epoch)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        fence: runne_application::ports::TaskRunFence(
            u64::try_from(fence).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        ),
    };
    super::super::super::taskrun_claim::verify_assignment_history(connection, &assignment)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if claim_version
        != i64::try_from(started_version)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        || admitted.len() != 16
        || started.len() != 16
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let settlement: Option<TerminalSettlementOccupationRow> = connection
        .query_row(
            "SELECT r.terminal_event_id,r.terminal_version,o.state,o.release_event_id
             FROM taskrun_terminal_settlement_receipts r
             JOIN taskrun_assignment_occupations o ON o.taskrun_id=r.taskrun_id AND o.fence=r.fence
               AND o.attempt_id=r.attempt_id AND o.node_id=r.node_id AND o.node_epoch=r.node_epoch
               AND o.dispatch_intent='absent'
             WHERE r.taskrun_id=?1 AND r.attempt_id=?2 AND r.node_id=?3 AND r.node_epoch=?4 AND r.fence=?5",
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes(), node, epoch, fence],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    match settlement {
        Some((event_id, version, state, release))
            if state == "released"
                && release.as_deref() == Some(event_id.as_slice())
                && event_id.as_slice() == terminal_event_id(connection, receipt)?.as_slice()
                && version
                    == i64::try_from(receipt.taskrun_version)
                        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))? =>
        {
            Ok(())
        }
        _ => Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    }
}

fn terminal_event_id(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<Vec<u8>, CommitError> {
    connection
        .query_row(
            "SELECT event_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
            params![receipt.taskrun_id.as_bytes(), i64::try_from(receipt.taskrun_version).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))
}
