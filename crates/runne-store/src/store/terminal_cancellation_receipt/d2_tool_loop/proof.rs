use super::*;

type ClaimIdentity = (i64, Vec<u8>, i64, i64);

pub(super) fn verify(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    terminal_event_id: &[u8],
) -> Result<(), CommitError> {
    let identity: Option<ClaimIdentity> = connection
        .query_row(
            "SELECT fence,node_id,node_epoch,new_version FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2",
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| invalid())?;
    let Some((fence, node, epoch, original_claim_version)) = identity else {
        return Err(invalid());
    };
    let budget_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            [receipt.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    if budget_rows > 0 {
        let exact_budget: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2
                 AND fence=?3 AND node_id=?4 AND node_epoch=?5
                 AND policy_revision='d2-safe-tool-loop-budget-v1')",
                params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes(), fence, uuid::Uuid::from_slice(&node).map_err(|_| invalid())?.to_string(), epoch],
                |row| row.get(0),
            )
            .map_err(|_| invalid())?;
        if !exact_budget {
            return Err(invalid());
        }
    }
    let linked: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts s
             JOIN taskrun_assignment_occupations o ON o.taskrun_id=s.taskrun_id AND o.fence=s.fence
              AND o.attempt_id=s.attempt_id AND o.node_id=s.node_id AND o.node_epoch=s.node_epoch
             WHERE s.taskrun_id=?1 AND s.attempt_id=?2 AND s.fence=?3 AND s.node_id=?4
              AND s.node_epoch=?5 AND s.terminal_event_id=?6 AND s.terminal_version=?7
              AND o.state='released' AND o.release_event_id=?6)",
            params![
                receipt.taskrun_id.as_bytes(),
                receipt.attempt_id.as_bytes(),
                fence,
                node,
                epoch,
                terminal_event_id,
                receipt.taskrun_version as i64,
            ],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    if !linked {
        return Err(invalid());
    }
    invocations::verify(connection, receipt, fence, &node, epoch)?;
    let evidence = runne_application::ports::D2ToolLoopCancellationEvidence {
        node_id: node.as_slice().try_into().map_err(|_| invalid())?,
        node_epoch: u64::try_from(epoch).map_err(|_| invalid())?,
        fence: u64::try_from(fence).map_err(|_| invalid())?,
        cancellation_taskrun_version: receipt.taskrun_version.checked_sub(1).ok_or_else(invalid)?,
    };
    crate::store::verify_d2_cancelled_provider_rounds(
        connection,
        receipt.taskrun_id,
        receipt.attempt_id,
        evidence,
        u64::try_from(original_claim_version).map_err(|_| invalid())?,
        evidence.cancellation_taskrun_version,
    )
}

fn invalid() -> CommitError {
    super::super::super::parse_helpers::storage_failure(StorageFailureKind::IntegrityViolation)
}
