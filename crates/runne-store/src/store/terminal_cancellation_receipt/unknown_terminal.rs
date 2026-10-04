use super::super::parse_helpers::storage_failure;
use super::super::*;

pub(super) fn validate_evidence(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    evidence: runne_application::ports::ProviderUnknownTerminalCancellationEvidence,
) -> Result<bool, CommitError> {
    let disposition_code = match evidence.disposition {
        runne_provider::ProviderTerminalDisposition::Completed => 1,
        runne_provider::ProviderTerminalDisposition::RemoteFailed => 2,
        runne_provider::ProviderTerminalDisposition::RemoteIncomplete => 3,
        runne_provider::ProviderTerminalDisposition::CancelledUncertain => return Ok(false),
    };
    if evidence.cancellation_taskrun_version.checked_add(1) != Some(receipt.taskrun_version) {
        return Ok(false);
    }
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM provider_unknown_terminal_receipts u
                JOIN provider_dispatch_attempts d ON d.attempt_id=u.dispatch_attempt_id
                WHERE u.dispatch_attempt_id=?1 AND u.taskrun_id=?2
                  AND u.taskrun_attempt_id=?3 AND u.conversation_id=?4
                  AND u.terminal_disposition=?6 AND u.unknown_commitment=?5
                  AND d.state=CASE WHEN ?6=1 THEN 4 ELSE 5 END
                  AND d.settlement_digest=u.unknown_commitment
                  AND ((?6=1 AND ((u.outbox_id IS NULL
                        AND u.application_idempotency_key IS NULL
                        AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox o
                          WHERE o.dispatch_attempt_id=d.attempt_id))
                      OR (u.outbox_id IS NOT NULL AND u.application_idempotency_key IS NOT NULL
                        AND EXISTS(SELECT 1 FROM provider_terminal_outbox o
                          WHERE o.outbox_id=u.outbox_id AND o.dispatch_attempt_id=d.attempt_id
                            AND o.application_idempotency_key=u.application_idempotency_key
                            AND o.settlement_digest=u.unknown_commitment))))
                    OR (?6 IN (2,3) AND u.outbox_id IS NULL
                      AND u.application_idempotency_key IS NULL
                      AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox o
                        WHERE o.dispatch_attempt_id=d.attempt_id)))
                  AND NOT EXISTS(SELECT 1 FROM provider_accounting_settlements s
                    WHERE s.dispatch_attempt_id=d.attempt_id)
                  AND NOT EXISTS(SELECT 1 FROM provider_terminal_dispositions m
                    WHERE m.dispatch_attempt_id=d.attempt_id))",
            params![
                evidence.dispatch_attempt_id.as_slice(),
                receipt.taskrun_id.as_bytes(),
                receipt.attempt_id.as_bytes(),
                receipt.conversation_id.as_bytes(),
                evidence.unknown_commitment.as_slice(),
                disposition_code,
            ],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

pub(super) fn validate_receipt(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM taskrun_terminal_settlement_receipts t
                JOIN taskrun_assignment_occupations o ON o.taskrun_id=t.taskrun_id
                  AND o.fence=t.fence AND o.attempt_id=t.attempt_id
                  AND o.node_id=t.node_id AND o.node_epoch=t.node_epoch
                  AND o.state='released' AND o.release_event_id=t.terminal_event_id
                JOIN provider_unknown_terminal_receipts u ON u.taskrun_id=t.taskrun_id
                  AND u.taskrun_attempt_id=t.attempt_id
                JOIN provider_dispatch_attempts d ON d.attempt_id=u.dispatch_attempt_id
                WHERE t.taskrun_id=?1 AND t.attempt_id=?2 AND t.terminal_version=?3
                  AND u.conversation_id=?4 AND u.terminal_disposition IN (1,2,3)
                  AND d.state=CASE WHEN u.terminal_disposition=1 THEN 4 ELSE 5 END
                  AND d.settlement_digest=u.unknown_commitment
                  AND ((u.terminal_disposition=1 AND ((u.outbox_id IS NULL
                        AND u.application_idempotency_key IS NULL
                        AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x
                          WHERE x.dispatch_attempt_id=d.attempt_id))
                      OR (u.outbox_id IS NOT NULL AND u.application_idempotency_key IS NOT NULL
                        AND EXISTS(SELECT 1 FROM provider_terminal_outbox x
                          WHERE x.outbox_id=u.outbox_id AND x.dispatch_attempt_id=d.attempt_id
                            AND x.application_idempotency_key=u.application_idempotency_key
                            AND x.settlement_digest=u.unknown_commitment))))
                    OR (u.terminal_disposition IN (2,3) AND u.outbox_id IS NULL
                      AND u.application_idempotency_key IS NULL
                      AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x
                        WHERE x.dispatch_attempt_id=d.attempt_id)))
                  AND NOT EXISTS(SELECT 1 FROM provider_accounting_settlements s
                    WHERE s.dispatch_attempt_id=d.attempt_id)
                  AND NOT EXISTS(SELECT 1 FROM provider_terminal_dispositions m
                    WHERE m.dispatch_attempt_id=d.attempt_id))",
            params![
                receipt.taskrun_id.as_bytes(),
                receipt.attempt_id.as_bytes(),
                i64::try_from(receipt.taskrun_version)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
                receipt.conversation_id.as_bytes(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}
