use super::*;
use crate::store::test_support_diagnostics as diagnostics;

pub(super) fn validate(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    evidence: runne_application::ports::D2ToolLoopCancellationEvidence,
) -> Result<(), CommitError> {
    if !diagnostics::on_error(
        "cancel.d2.validate_evidence_base",
        super::validate(connection, receipt),
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
    let verified = super::super::super::taskrun_claim::stream_validate::verify_stream(
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

fn invalid() -> CommitError {
    super::super::super::parse_helpers::storage_failure(StorageFailureKind::IntegrityViolation)
}
