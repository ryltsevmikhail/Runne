use super::super::*;
use super::record::{ProviderUnknownFailureRecoveryPage, ProviderUnknownFailureRecoveryRecord};
use crate::store::parse_helpers::storage_failure;
use runne_application::ports::{ExecutionNodeId, TaskRunFence};
use runne_provider::{ProviderCallDigestVersion, ProviderTerminalDisposition, ProviderUsage};

impl StoreTransaction {
    /// Returns bounded Source1 terminal failures whose accounting remains Unknown.
    pub fn provider_unknown_failure_recovery_candidates(
        &self,
        after: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<ProviderUnknownFailureRecoveryPage, CommitError> {
        if limit == 0 || limit > 128 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let mut statement = reader
            .prepare(
                "SELECT r.dispatch_attempt_id,r.taskrun_id,r.conversation_id,
                        r.taskrun_attempt_id,b.node_id,b.node_epoch,b.fence,b.claim_version,
                        a.principal_id,a.fencing_token,a.generation,a.profile_digest,
                        p.call_digest_version,r.terminal_sequence,r.terminal_disposition,
                        r.unknown_commitment,r.usage_present,r.input_tokens,r.output_tokens,
                        r.cached_input_tokens,r.reasoning_output_tokens,
                        CASE WHEN t.current_version=b.claim_version+1 THEN t.current_version END
                 FROM provider_unknown_terminal_receipts r
                 JOIN provider_dispatch_attempts d ON d.attempt_id=r.dispatch_attempt_id
                 JOIN provider_execution_admissions a ON a.dispatch_attempt_id=d.attempt_id
                   AND a.taskrun_id=r.taskrun_id AND a.execution_attempt_id=r.taskrun_attempt_id
                   AND a.conversation_id=r.conversation_id
                 JOIN taskrun_provider_bindings b ON b.taskrun_id=a.taskrun_id
                   AND b.attempt_id=a.execution_attempt_id AND b.call_id=a.call_id
                   AND b.provider_idempotency_key=a.provider_idempotency_key
                   AND b.prepared_digest=a.prepared_digest AND b.render_digest=a.render_digest
                   AND b.profile_digest=a.profile_digest
                 JOIN provider_prepared_requests p ON p.call_id=b.call_id
                   AND p.call_digest_version=b.call_digest_version
                   AND p.prepared_digest=b.prepared_digest AND p.render_digest=b.render_digest
                   AND p.profile_digest=b.profile_digest
                 JOIN taskrun_assignment_occupations o ON o.taskrun_id=b.taskrun_id
                   AND o.fence=b.fence AND o.attempt_id=b.attempt_id AND o.node_id=b.node_id
                   AND o.node_epoch=b.node_epoch AND o.state='active'
                   AND o.dispatch_intent='present'
                 JOIN taskrun_claim_receipts c ON c.taskrun_id=b.taskrun_id
                   AND c.fence=b.fence AND c.attempt_id=b.attempt_id AND c.node_id=b.node_id
                   AND c.node_epoch=b.node_epoch AND c.new_version=b.claim_version
                 JOIN aggregate_streams t ON t.aggregate_type=1 AND t.aggregate_id=b.taskrun_id
                   AND t.current_version IN (b.claim_version,b.claim_version+1)
                 WHERE r.terminal_disposition IN (2,3) AND d.state=5
                   AND d.settlement_digest=r.unknown_commitment
                   AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x
                     WHERE x.dispatch_attempt_id=d.attempt_id)
                   AND NOT EXISTS(SELECT 1 FROM provider_accounting_settlements s
                     WHERE s.dispatch_attempt_id=d.attempt_id)
                   AND NOT EXISTS(SELECT 1 FROM provider_terminal_dispositions m
                     WHERE m.dispatch_attempt_id=d.attempt_id)
                   AND NOT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts x
                     WHERE x.taskrun_id=b.taskrun_id)
                   AND (?1 IS NULL OR r.dispatch_attempt_id>?1)
                 ORDER BY r.dispatch_attempt_id LIMIT ?2",
            )
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let rows = statement
            .query_map(
                rusqlite::params![
                    after.as_ref().map(|id| id.as_slice()),
                    i64::try_from(limit).unwrap_or(128),
                ],
                |row| {
                    let taskrun_id = TaskRunId::from_bytes(fixed(row.get(1)?)?);
                    let conversation_id = ConversationId::from_bytes(fixed(row.get(2)?)?);
                    let attempt_id = AttemptId::from_bytes(fixed(row.get(3)?)?);
                    let node = fixed::<16>(row.get(4)?)?;
                    let disposition = match row.get::<_, i64>(14)? {
                        2 => ProviderTerminalDisposition::RemoteFailed,
                        3 => ProviderTerminalDisposition::RemoteIncomplete,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    let usage = match (
                        row.get::<_, i64>(16)?,
                        row.get::<_, Option<i64>>(17)?,
                        row.get::<_, Option<i64>>(18)?,
                        row.get::<_, Option<i64>>(19)?,
                        row.get::<_, Option<i64>>(20)?,
                    ) {
                        (0, None, None, None, None) => None,
                        (1, Some(input), Some(output), Some(cached), Some(reasoning)) => Some(
                            ProviderUsage::new(
                                nonnegative(input)?,
                                nonnegative(output)?,
                                nonnegative(cached)?,
                                nonnegative(reasoning)?,
                            )
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        ),
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    let call_digest_version = match row.get::<_, i64>(12)? {
                        1 => ProviderCallDigestVersion::V1,
                        2 => ProviderCallDigestVersion::V2,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    Ok(ProviderUnknownFailureRecoveryRecord {
                        dispatch_attempt_id: fixed(row.get(0)?)?,
                        taskrun_id,
                        conversation_id,
                        execution_attempt_id: attempt_id,
                        assignment: TaskRunAssignmentIdentity {
                            taskrun_id,
                            attempt_id,
                            node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
                            node_epoch: positive(row.get(5)?)?,
                            fence: TaskRunFence(positive(row.get(6)?)?),
                        },
                        claim_version: positive(row.get(7)?)?,
                        principal_id: row.get(8)?,
                        submitted_prompt: String::new(),
                        workspace_id: None,
                        submit_actor: None,
                        fencing_token: positive(row.get(9)?)?,
                        runtime_generation: positive(row.get(10)?)?,
                        profile_digest: fixed(row.get(11)?)?,
                        call_digest_version,
                        terminal_sequence: positive(row.get(13)?)?,
                        disposition,
                        usage,
                        unknown_commitment: fixed(row.get(15)?)?,
                        cancellation_taskrun_version: row
                            .get::<_, Option<i64>>(21)?
                            .map(positive)
                            .transpose()?,
                    })
                },
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let candidates = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let next_cursor = candidates.last().map(|row| row.dispatch_attempt_id);
        let reached_end = candidates.len() < limit;
        drop(statement);
        drop(reader);
        let mut validated = Vec::new();
        for mut candidate in candidates {
            let stream = self
                .load_task_run(candidate.taskrun_id)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            let version_ok = stream.current_version == candidate.claim_version
                || stream.current_version == candidate.claim_version.saturating_add(1);
            let cancellation_ok = candidate
                .cancellation_taskrun_version
                .is_none_or(|version| {
                    version == stream.current_version
                        && stream.events.last().is_some_and(|event| {
                            event.payload()
                                == &runne_domain::task_run::TaskRunEvent::CancellationRequested
                        })
                });
            if !version_ok || !cancellation_ok {
                continue;
            }
            if let Some((prompt, workspace, actor)) = super::validate_submitter_identity(
                self,
                candidate.taskrun_id,
                candidate.conversation_id,
                &candidate.principal_id,
            )? {
                candidate.submitted_prompt = prompt;
                candidate.workspace_id = Some(workspace);
                candidate.submit_actor = Some(actor);
                validated.push(candidate);
            }
        }
        Ok(ProviderUnknownFailureRecoveryPage {
            candidates: validated,
            next_cursor,
            reached_end,
        })
    }
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn positive(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn nonnegative(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}
