use super::*;

pub(super) fn verify(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
    dispatch_id: [u8; 16],
) -> Result<bool, CommitError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions a
         JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
           AND d.call_id=a.call_id AND d.provider_idempotency_key=a.provider_idempotency_key
           AND d.fencing_token=a.fencing_token AND d.profile_digest=a.profile_digest
           AND d.prepared_digest=a.prepared_digest AND d.render_digest=a.render_digest
         JOIN provider_prepared_requests p ON p.call_id=a.call_id
           AND p.prepared_digest=a.prepared_digest AND p.render_digest=a.render_digest
           AND p.profile_digest=a.profile_digest
         JOIN taskrun_assignment_occupations o ON o.taskrun_id=a.taskrun_id
           AND o.attempt_id=a.execution_attempt_id AND o.state='active' AND o.release_event_id IS NULL
         JOIN taskrun_claim_receipts c ON c.taskrun_id=o.taskrun_id AND c.attempt_id=o.attempt_id
           AND c.fence=o.fence AND c.node_id=o.node_id AND c.node_epoch=o.node_epoch
           AND c.new_version=?6
         LEFT JOIN taskrun_provider_bindings b ON b.taskrun_id=a.taskrun_id
         WHERE a.dispatch_attempt_id=?1 AND a.taskrun_id=?2 AND a.conversation_id=?3
           AND a.execution_attempt_id=?4 AND a.principal_id=?5
           AND d.state=2 AND d.pre_effect_rejection BETWEEN 1 AND 7
           AND d.call_id=a.call_id AND d.provider_idempotency_key=a.provider_idempotency_key
           AND d.profile_digest=a.profile_digest AND d.prepared_digest=a.prepared_digest
           AND d.render_digest=a.render_digest AND d.fencing_token=a.fencing_token
           AND o.fence=c.fence AND o.node_id=c.node_id AND o.node_epoch=c.node_epoch
           AND NOT EXISTS(SELECT 1 FROM provider_effect_starts e WHERE e.dispatch_attempt_id=d.attempt_id)
           AND NOT EXISTS(SELECT 1 FROM provider_stream_journal j WHERE j.dispatch_attempt_id=d.attempt_id)
           AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x WHERE x.dispatch_attempt_id=d.attempt_id)
           AND NOT EXISTS(SELECT 1 FROM provider_accounting_settlements s WHERE s.dispatch_attempt_id=d.attempt_id)
           AND NOT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r WHERE r.taskrun_id=a.taskrun_id)
           AND NOT EXISTS(SELECT 1 FROM provider_execution_admissions other WHERE other.taskrun_id=a.taskrun_id
             AND other.execution_attempt_id=a.execution_attempt_id AND other.dispatch_attempt_id<>a.dispatch_attempt_id)
           AND EXISTS(SELECT 1 FROM provider_runtime_authority_state r
             WHERE r.id=1 AND r.active=1 AND r.runtime_authority_id=?7
               AND r.lease_generation>0 AND r.lease_fencing_token>0)
           AND ((o.dispatch_intent='absent' AND b.taskrun_id IS NULL
                 AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=o.taskrun_id AND i.fence=o.fence))
             OR (o.dispatch_intent='present' AND b.taskrun_id=a.taskrun_id
                 AND b.attempt_id=a.execution_attempt_id AND b.fence=o.fence AND b.node_id=o.node_id
                 AND b.node_epoch=o.node_epoch AND b.claim_version=c.new_version
                 AND b.call_digest_version=p.call_digest_version AND b.call_id=a.call_id
                 AND b.provider_idempotency_key=a.provider_idempotency_key
                 AND b.prepared_digest=a.prepared_digest AND b.render_digest=a.render_digest
                 AND b.profile_digest=a.profile_digest
                 AND EXISTS(SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=o.taskrun_id
                   AND i.fence=o.fence AND i.attempt_id=o.attempt_id AND i.node_id=o.node_id
                   AND i.node_epoch=o.node_epoch AND i.state='present'))))",
        rusqlite::params![dispatch_id.as_slice(), payload.receipt.taskrun_id.as_bytes(),
            payload.receipt.conversation_id.as_bytes(), payload.receipt.attempt_id.as_bytes(),
            payload.idempotency_scope.principal_id.0,
            payload.expected_started_taskrun_version as i64,
            uuid::Uuid::parse_str(&payload.idempotency_scope.runtime_authority_id.0)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?
                .as_bytes()],
        |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}
