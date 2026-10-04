use super::*;

impl StoreTransaction {
    /// Returns exact active claimed TaskRuns with a durable pre-effect rejection
    /// and no provider effect-start or journal evidence.
    pub fn provider_rejection_recovery_candidates(
        &self,
        after: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<ProviderFailureRecoveryPage, CommitError> {
        if limit == 0 || limit > 128 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let mut statement = reader.prepare(
            "SELECT a.dispatch_attempt_id,a.taskrun_id,a.conversation_id,a.execution_attempt_id,
                    o.node_id,o.node_epoch,o.fence,c.new_version,a.principal_id,a.generation,
                    d.fencing_token,a.profile_digest,d.pre_effect_rejection,
                    CASE WHEN t.current_version=c.new_version+1 THEN t.current_version END
             FROM provider_execution_admissions a
             JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
                  AND d.call_id=a.call_id AND d.provider_idempotency_key=a.provider_idempotency_key
                  AND d.fencing_token=a.fencing_token AND d.profile_digest=a.profile_digest
                  AND d.prepared_digest=a.prepared_digest AND d.render_digest=a.render_digest AND d.state=2
                  AND d.pre_effect_rejection BETWEEN 1 AND 7
             JOIN provider_prepared_requests p ON p.call_id=a.call_id
                  AND p.prepared_digest=a.prepared_digest AND p.render_digest=a.render_digest
                  AND p.profile_digest=a.profile_digest
             JOIN taskrun_assignment_occupations o ON o.taskrun_id=a.taskrun_id
                  AND o.attempt_id=a.execution_attempt_id
                  AND o.state='active' AND o.dispatch_intent IN ('absent','present')
             LEFT JOIN taskrun_provider_bindings b ON b.taskrun_id=a.taskrun_id
             JOIN taskrun_claim_receipts c ON c.taskrun_id=o.taskrun_id AND c.attempt_id=o.attempt_id
                  AND c.fence=o.fence AND c.node_id=o.node_id AND c.node_epoch=o.node_epoch
             JOIN aggregate_streams t ON t.aggregate_type=1 AND t.aggregate_id=o.taskrun_id
                  AND t.current_version IN (c.new_version,c.new_version+1)
             WHERE NOT EXISTS(SELECT 1 FROM provider_effect_starts e WHERE e.dispatch_attempt_id=d.attempt_id)
               AND NOT EXISTS(SELECT 1 FROM provider_stream_journal j WHERE j.dispatch_attempt_id=d.attempt_id)
               AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x WHERE x.dispatch_attempt_id=d.attempt_id)
               AND NOT EXISTS(SELECT 1 FROM provider_accounting_settlements s WHERE s.dispatch_attempt_id=d.attempt_id)
               AND ((o.dispatch_intent='absent' AND b.taskrun_id IS NULL)
                    OR (o.dispatch_intent='present' AND b.taskrun_id IS NOT NULL
                    AND b.attempt_id=a.execution_attempt_id AND b.fence=o.fence
                    AND b.node_id=o.node_id AND b.node_epoch=o.node_epoch AND b.claim_version=c.new_version
                    AND b.call_digest_version=p.call_digest_version AND b.call_id=a.call_id
                    AND b.provider_idempotency_key=a.provider_idempotency_key
                    AND b.prepared_digest=a.prepared_digest AND b.render_digest=a.render_digest
                    AND b.profile_digest=a.profile_digest))
               AND ((o.dispatch_intent='absent' AND NOT EXISTS(
                      SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=o.taskrun_id AND i.fence=o.fence))
                    OR (o.dispatch_intent='present' AND EXISTS(
                      SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=o.taskrun_id
                        AND i.fence=o.fence AND i.attempt_id=o.attempt_id AND i.node_id=o.node_id
                        AND i.node_epoch=o.node_epoch AND i.state='present')))
               AND NOT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts x WHERE x.taskrun_id=a.taskrun_id)
               AND NOT EXISTS(SELECT 1 FROM provider_execution_admissions other
                              WHERE other.taskrun_id=a.taskrun_id AND other.execution_attempt_id=a.execution_attempt_id
                                AND other.dispatch_attempt_id<>a.dispatch_attempt_id)
               AND (?1 IS NULL OR d.attempt_id>?1)
             ORDER BY d.attempt_id LIMIT ?2",
        ).map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let rows = statement
            .query_map(
                rusqlite::params![
                    after.as_ref().map(|id| id.as_slice()),
                    i64::try_from(limit).unwrap_or(128)
                ],
                |row| {
                    let taskrun_id = TaskRunId::from_bytes(failure_fixed(row.get(1)?)?);
                    let attempt_id = AttemptId::from_bytes(failure_fixed(row.get(3)?)?);
                    let claim_version = failure_positive(row.get(7)?)?;
                    Ok(ProviderFailureRecoveryRecord {
                        kind: ProviderFailureRecoveryKind::RejectedBeforeEffect,
                        pre_effect_rejection: Some(row.get(12)?),
                        dispatch_attempt_id: failure_fixed(row.get(0)?)?,
                        taskrun_id,
                        conversation_id: ConversationId::from_bytes(failure_fixed(row.get(2)?)?),
                        execution_attempt_id: attempt_id,
                        assignment: TaskRunAssignmentIdentity {
                            taskrun_id,
                            attempt_id,
                            node_id: ExecutionNodeId(
                                uuid::Uuid::from_bytes(failure_fixed(row.get(4)?)?).to_string(),
                            ),
                            node_epoch: failure_positive(row.get(5)?)?,
                            fence: TaskRunFence(failure_positive(row.get(6)?)?),
                        },
                        claim_version,
                        principal_id: row.get(8)?,
                        submitted_prompt: String::new(),
                        workspace_id: None,
                        submit_actor: None,
                        runtime_generation: failure_positive(row.get(9)?)?,
                        provider_fencing_token: failure_positive(row.get(10)?)?,
                        profile_digest: failure_fixed(row.get(11)?)?,
                        pricing_revision_digest: [0; 32],
                        settlement_digest: [0; 32],
                        input_tokens: 0,
                        output_tokens: 0,
                        cached_input_tokens: 0,
                        reasoning_output_tokens: 0,
                        charge_micros: 0,
                        currency: String::new(),
                        cancellation_taskrun_version: row
                            .get::<_, Option<i64>>(13)?
                            .map(failure_positive)
                            .transpose()?,
                        terminal_disposition: None,
                    })
                },
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let mut raw = Vec::new();
        for row in rows {
            raw.push(row.map_err(|_| storage_failure(StorageFailureKind::CorruptData))?);
        }
        let next_cursor = raw.last().map(|record| record.dispatch_attempt_id);
        let reached_end = raw.len() < limit;
        drop(statement);
        drop(reader);
        let mut candidates = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for mut candidate in raw {
            if !seen.insert(candidate.dispatch_attempt_id) {
                return Err(storage_failure(StorageFailureKind::CorruptData));
            }
            if let Some((prompt, workspace, actor)) = validate_submitter(self, &candidate)? {
                candidate.submitted_prompt = prompt;
                candidate.workspace_id = Some(workspace);
                candidate.submit_actor = Some(actor);
                candidates.push(candidate);
            }
        }
        Ok(ProviderFailureRecoveryPage {
            candidates,
            next_cursor,
            reached_end,
        })
    }
}
