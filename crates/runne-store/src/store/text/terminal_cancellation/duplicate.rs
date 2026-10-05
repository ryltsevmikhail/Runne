use super::super::parse_helpers::storage_failure;
use super::super::*;
use runne_application::ports::{
    ProviderCancellationProof, ProviderTerminalCancellationEvidence,
    ProviderUnknownTerminalCancellationEvidence, RejectTextGenerationAfterCancellationCommit,
};
use rusqlite::{Transaction, params};

pub(super) fn validate(
    tx: &Transaction<'_>,
    stored: &TextGenerationReceipt,
    payload: &RejectTextGenerationAfterCancellationCommit,
    terminal: Option<ProviderTerminalCancellationEvidence>,
    dispatch_attempt_id: Option<[u8; 16]>,
    unknown: Option<ProviderUnknownTerminalCancellationEvidence>,
) -> Result<bool, CommitError> {
    if let ProviderCancellationProof::D2ToolLoop(evidence) = payload.proof {
        let exact: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts c
             JOIN taskrun_terminal_settlement_receipts s ON s.taskrun_id=c.taskrun_id
              AND s.fence=c.fence AND s.attempt_id=c.attempt_id AND s.node_id=c.node_id AND s.node_epoch=c.node_epoch
             WHERE c.taskrun_id=?1 AND c.attempt_id=?2 AND c.node_id=?3 AND c.node_epoch=?4
              AND c.fence=?5 AND s.terminal_version=?6 AND s.terminal_event_id=(
                SELECT event_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?6))",
            params![stored.taskrun_id.as_bytes(), stored.attempt_id.as_bytes(), evidence.node_id.as_slice(),
                evidence.node_epoch as i64, evidence.fence as i64, stored.taskrun_version as i64],
            |row| row.get(0),
        ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        return Ok(exact
            && evidence.cancellation_taskrun_version.checked_add(1) == Some(stored.taskrun_version)
            && super::super::super::terminal_cancellation_receipt::validate_terminal_cancellation_receipt(tx, stored).is_ok());
    }
    if let Some(evidence) = terminal {
        let dispatch = dispatch_attempt_id
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
        return tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r
                 JOIN events e ON e.event_id=r.terminal_event_id
                 JOIN taskrun_assignment_occupations o USING(taskrun_id,fence)
                 JOIN provider_terminal_dispositions d ON d.dispatch_attempt_id=?2
                 JOIN provider_dispatch_attempts p ON p.attempt_id=d.dispatch_attempt_id
                 WHERE r.taskrun_id=?1 AND r.attempt_id=?3 AND r.terminal_version=?6
                   AND e.aggregate_type=1 AND e.aggregate_id=r.taskrun_id AND e.sequence=r.terminal_version
                   AND o.state='released' AND o.release_event_id=r.terminal_event_id
                   AND p.settlement_digest=?4 AND d.disposition=?5)",
                params![
                    stored.taskrun_id.as_bytes(),
                    dispatch.as_slice(),
                    stored.attempt_id.as_bytes(),
                    evidence.settlement_digest.as_slice(),
                    super::disposition::terminal_disposition_code(evidence.disposition),
                    stored.taskrun_version as i64,
                ],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData));
    }
    if let ProviderCancellationProof::NoAdmission(evidence) = payload.proof {
        return Ok(evidence.cancellation_taskrun_version.checked_add(1)
            == Some(stored.taskrun_version)
            && super::super::terminal_cancellation_receipt::validate_no_admission_receipt(
                tx, stored,
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?);
    }
    if let Some(evidence) = unknown {
        return super::super::terminal_cancellation_receipt::validate_unknown_terminal_cancellation(
            tx, stored, evidence,
        );
    }
    if let Some(dispatch) = dispatch_attempt_id {
        return tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r
                 JOIN taskrun_assignment_occupations o USING(taskrun_id,fence)
                 JOIN provider_execution_admissions a ON a.taskrun_id=r.taskrun_id
                   AND a.execution_attempt_id=r.attempt_id AND a.dispatch_attempt_id=?2
                 JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
                   AND d.state=2 AND d.pre_effect_rejection BETWEEN 1 AND 7
                 WHERE r.taskrun_id=?1 AND r.attempt_id=?3 AND r.terminal_version=?4
                   AND o.state='released' AND o.release_event_id=r.terminal_event_id
                   AND NOT EXISTS(SELECT 1 FROM provider_effect_starts x WHERE x.dispatch_attempt_id=d.attempt_id)
                   AND NOT EXISTS(SELECT 1 FROM provider_stream_journal x WHERE x.dispatch_attempt_id=d.attempt_id)
                   AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x WHERE x.dispatch_attempt_id=d.attempt_id)
                   AND NOT EXISTS(SELECT 1 FROM provider_accounting_settlements x WHERE x.dispatch_attempt_id=d.attempt_id))",
                params![
                    stored.taskrun_id.as_bytes(),
                    dispatch.as_slice(),
                    stored.attempt_id.as_bytes(),
                    stored.taskrun_version as i64,
                ],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData));
    }
    Ok(false)
}
