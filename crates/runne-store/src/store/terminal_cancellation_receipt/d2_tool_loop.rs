use super::super::test_support_diagnostics as diagnostics;
use super::super::*;
use runne_application::ports::TextGenerationPhase;
use runne_domain::task_run::{TaskRun, TaskRunState};
use rusqlite::{Connection, OptionalExtension, params};

#[path = "d2_tool_loop/conversation.rs"]
mod conversation;

type InvocationRow = (
    Vec<u8>,
    u32,
    String,
    Option<i64>,
    Option<String>,
    Option<i64>,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
);

pub(super) fn validate(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    if receipt.phase != TextGenerationPhase::Rejected {
        return Ok(false);
    }
    let budget_table_installed: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
             AND name='taskrun_tool_budgets')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    if !budget_table_installed {
        return Ok(false);
    }
    let taskrun = super::super::taskrun_claim::stream_validate::verify_stream(
        connection,
        receipt.taskrun_id,
        Some(receipt.taskrun_version),
    )
    .map_err(|_| invalid())?;
    if TaskRun::replay(&taskrun.events)
        .map_err(|_| invalid())?
        .state()
        != TaskRunState::Cancelled
        || taskrun
            .events
            .last()
            .is_none_or(|event| event.payload() != &TaskRunEvent::CancellationCompleted)
        || !taskrun
            .events
            .iter()
            .any(|event| event.payload() == &TaskRunEvent::CancellationRequested)
    {
        return Err(invalid());
    }
    let terminal = taskrun.events.last().ok_or_else(invalid)?;
    let identity: Option<(i64, Vec<u8>, i64)> = connection.query_row(
        "SELECT fence,node_id,node_epoch FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2",
        params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|_| invalid())?;
    let Some((fence, node, epoch)) = identity else {
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
          AND o.state='released' AND o.release_event_id=?6
          )",
            params![
                receipt.taskrun_id.as_bytes(),
                receipt.attempt_id.as_bytes(),
                fence,
                node,
                epoch,
                terminal.event_id().as_bytes(),
                receipt.taskrun_version as i64,
            ],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    if !linked {
        return Err(invalid());
    }
    verify_invocations(connection, receipt, fence, &node, epoch)?;
    conversation::verify_conversation(connection, receipt)?;
    Ok(true)
}

pub(super) fn validate_evidence(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    evidence: runne_application::ports::D2ToolLoopCancellationEvidence,
) -> Result<(), CommitError> {
    if !diagnostics::on_error(
        "cancel.d2.validate_evidence_base",
        validate(connection, receipt),
    )? || receipt.taskrun_version
        != evidence
            .cancellation_taskrun_version
            .checked_add(1)
            .ok_or_else(invalid)?
    {
        diagnostics::record("cancel.d2.evidence_receipt_version");
        return Err(invalid());
    }
    let assignment: Option<(i64, Vec<u8>, i64, i64)> = diagnostics::on_error(
        "cancel.d2.evidence_assignment_query",
        connection
            .query_row(
                "SELECT fence,node_id,node_epoch,new_version FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2",
                params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| invalid()),
    )?;
    let Some((fence, node, epoch, original_claim_version)) = assignment else {
        return Err(invalid());
    };
    if fence != evidence.fence as i64
        || node.as_slice() != evidence.node_id
        || epoch != evidence.node_epoch as i64
    {
        diagnostics::record("cancel.d2.evidence_assignment");
        return Err(invalid());
    }
    let verified = super::super::taskrun_claim::stream_validate::verify_stream(
        connection,
        receipt.taskrun_id,
        None,
    )
    .map_err(|_| invalid())?;
    let end = usize::try_from(evidence.cancellation_taskrun_version).map_err(|_| invalid())?;
    if end > verified.events.len()
        || TaskRun::replay(&verified.events[..end])
            .map_err(|_| invalid())?
            .state()
            != TaskRunState::Cancelling
        || verified.events[..end]
            .last()
            .is_none_or(|event| event.payload() != &TaskRunEvent::CancellationRequested)
    {
        diagnostics::record("cancel.d2.evidence_requested_event");
        return Err(invalid());
    }
    diagnostics::on_error(
        "cancel.d2.evidence_rounds",
        crate::store::verify_d2_cancelled_provider_rounds(
            connection,
            receipt.taskrun_id,
            receipt.attempt_id,
            evidence,
            u64::try_from(original_claim_version).map_err(|_| invalid())?,
            evidence.cancellation_taskrun_version,
        )
        .map_err(|_| invalid()),
    )?;
    Ok(())
}

fn verify_invocations(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    fence: i64,
    node: &[u8],
    epoch: i64,
) -> Result<(), CommitError> {
    let mut query = connection.prepare(
        "SELECT cycle_id,proposal_index,state,claim_fence,claim_node_id,claim_node_epoch,release_started,
          local_stop_state,managed_area_identity,empty_proof_identity,semantic_digest,result_truncated
         FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 ORDER BY cycle_id,proposal_index",
    ).map_err(|_| invalid())?;
    let rows: Vec<InvocationRow> = query
        .query_map(
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                ))
            },
        )
        .map_err(|_| invalid())?
        .collect::<Result<_, _>>()
        .map_err(|_| invalid())?;
    if rows.len() > 2 {
        return Err(invalid());
    }
    for (
        cycle,
        index,
        state,
        claim_fence,
        claim_node,
        claim_epoch,
        release,
        stop,
        area,
        proof,
        semantic,
        truncated,
    ) in rows
    {
        let claimed = match (claim_fence, claim_node.as_deref(), claim_epoch) {
            (Some(f), Some(n), Some(e)) => {
                f == fence
                    && n == uuid::Uuid::from_slice(node)
                        .map_err(|_| invalid())?
                        .to_string()
                    && e == epoch
            }
            (None, None, None) => matches!(state.as_str(), "proposed" | "approved" | "denied"),
            _ => false,
        };
        let area_valid = match (stop, area.as_ref(), proof.as_ref(), semantic.as_ref()) {
            (0, None, None, _) => release == 0,
            (2, Some(a), Some(p), Some(d)) if a == p && d.len() == 32 => {
                let identity =
                    runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(a)
                        .map_err(|_| invalid())?;
                let bytes = identity.to_bytes();
                let cycle: [u8; 16] = cycle.as_slice().try_into().map_err(|_| invalid())?;
                let key = crate::store::taskrun_tool_invocation::ToolInvocationKey {
                    taskrun_id: receipt.taskrun_id,
                    attempt_id: receipt.attempt_id,
                    cycle_id: runne_domain::id::CycleId::from_bytes(cycle),
                    proposal_index: index,
                };
                let digest = runne_domain::id::IntegrityDigest::from_bytes(
                    d.as_slice().try_into().map_err(|_| invalid())?,
                );
                bytes[52..68] == *receipt.taskrun_id.as_bytes()
                    && bytes[68..84] == *receipt.attempt_id.as_bytes()
                    && bytes[84..100] == key.managed_area_nonce(digest)
            }
            _ => false,
        };
        let known = match state.as_str() {
            "proposed" | "approved" | "denied" => stop == 0 && area.is_none() && release == 0,
            "claimed" | "cancelled" => area_valid,
            "uncertain" | "audit_only" => stop == 2 && area_valid,
            "result" => stop == 2 && area_valid && truncated == Some(0),
            _ => false,
        };
        if !claimed || !known {
            return Err(invalid());
        }
    }
    Ok(())
}

fn invalid() -> CommitError {
    super::super::parse_helpers::storage_failure(StorageFailureKind::IntegrityViolation)
}
