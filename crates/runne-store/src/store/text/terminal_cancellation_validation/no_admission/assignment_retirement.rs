use super::*;

pub(super) fn retire_claim(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
) -> Result<(), CommitError> {
    let assignment_count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1",
            [payload.receipt.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let occupation_count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
            [payload.receipt.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let claim_count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1",
            [payload.receipt.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if assignment_count == 0 && occupation_count == 0 && claim_count == 0 {
        return Ok(());
    }
    if assignment_count != 1 || occupation_count != 1 || claim_count != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let row: (Vec<u8>, i64, i64, String, Option<Vec<u8>>) = tx
        .query_row(
            "SELECT c.node_id,c.node_epoch,c.fence,o.dispatch_intent,o.release_event_id
         FROM taskrun_claim_receipts c
         JOIN taskrun_assignments a ON a.taskrun_id=c.taskrun_id AND a.fence=c.fence
           AND a.attempt_id=c.attempt_id AND a.node_id=c.node_id AND a.node_epoch=c.node_epoch
           AND a.command_id=c.command_id AND a.admitted_event_id=c.admitted_event_id
           AND a.started_event_id=c.started_event_id
         JOIN taskrun_assignment_occupations o ON o.taskrun_id=c.taskrun_id AND o.fence=c.fence
           AND o.attempt_id=c.attempt_id AND o.node_id=c.node_id AND o.node_epoch=c.node_epoch
        WHERE c.taskrun_id=?1 AND c.attempt_id=?2 AND c.new_version=?3
           AND o.state='active' AND o.dispatch_intent='absent' AND o.release_event_id IS NULL",
            params![
                payload.receipt.taskrun_id.as_bytes(),
                payload.receipt.attempt_id.as_bytes(),
                i64::try_from(payload.expected_started_taskrun_version)
                    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let node_bytes = row.0.clone();
    if row.3 != "absent" || row.4.is_some() {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let identity = TaskRunAssignmentIdentity {
        taskrun_id: payload.receipt.taskrun_id,
        attempt_id: payload.receipt.attempt_id,
        node_id: runne_application::ports::ExecutionNodeId(
            uuid::Uuid::from_bytes(
                node_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            )
            .to_string(),
        ),
        node_epoch: u64::try_from(row.1)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        fence: runne_application::ports::TaskRunFence(
            u64::try_from(row.2).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        ),
    };
    let fence = i64::try_from(identity.fence.0)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let node_epoch = i64::try_from(identity.node_epoch)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    tx.execute(
        "INSERT INTO taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![payload.receipt.taskrun_id.as_bytes(), fence, payload.receipt.attempt_id.as_bytes(),
            node_bytes.as_slice(), node_epoch, payload.taskrun_events[0].event_id().as_bytes(),
            i64::try_from(payload.receipt.taskrun_version).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?],
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if tx
        .execute(
            "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1
         WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6
           AND state='active' AND dispatch_intent='absent' AND release_event_id IS NULL",
            params![
                payload.taskrun_events[0].event_id().as_bytes(),
                payload.receipt.taskrun_id.as_bytes(),
                fence,
                payload.receipt.attempt_id.as_bytes(),
                node_bytes.as_slice(),
                node_epoch
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?
        != 1
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}
