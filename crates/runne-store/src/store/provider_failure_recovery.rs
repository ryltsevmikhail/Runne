use super::*;
use crate::store::parse_helpers::storage_failure;
use runne_application::ports::{ExecutionNodeId, TaskRunFence};
use runne_domain::event::Actor;
use runne_domain::id::WorkspaceId;
use runne_provider::ProviderTerminalDisposition;

mod record;
mod rejected;
mod unknown;
pub use record::*;

impl StoreTransaction {
    /// Returns at most `limit` exact active TaskRun/provider pairs with a committed
    /// non-success settlement. The authenticated journal and digest are checked by
    /// the daemon before any text receipt is changed.
    pub fn provider_failure_recovery_candidates(
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
                    b.node_id,b.node_epoch,b.fence,b.claim_version,a.principal_id,a.generation,a.fencing_token,
                    a.profile_digest,s.pricing_revision_digest,d.settlement_digest,
                    s.input_tokens,s.output_tokens,s.cached_input_tokens,s.reasoning_output_tokens,
                    s.charge_micros,s.currency,
                    CASE WHEN t.current_version=b.claim_version+1 THEN t.current_version END,
                    m.disposition
             FROM provider_execution_admissions a
             JOIN taskrun_provider_bindings b ON b.taskrun_id=a.taskrun_id
                  AND b.attempt_id=a.execution_attempt_id AND b.call_id=a.call_id
                  AND b.provider_idempotency_key=a.provider_idempotency_key
                  AND b.prepared_digest=a.prepared_digest AND b.render_digest=a.render_digest AND b.profile_digest=a.profile_digest
             JOIN provider_prepared_requests p ON p.call_id=b.call_id
                  AND p.call_digest_version=b.call_digest_version AND p.prepared_digest=b.prepared_digest
                  AND p.render_digest=b.render_digest AND p.profile_digest=b.profile_digest
             JOIN taskrun_assignment_occupations o ON o.taskrun_id=b.taskrun_id AND o.fence=b.fence
                  AND o.attempt_id=b.attempt_id AND o.node_id=b.node_id AND o.node_epoch=b.node_epoch
             JOIN taskrun_claim_receipts c ON c.taskrun_id=b.taskrun_id AND c.fence=b.fence
                  AND c.attempt_id=b.attempt_id AND c.node_id=b.node_id AND c.node_epoch=b.node_epoch
                  AND c.new_version=b.claim_version
             JOIN aggregate_streams t ON t.aggregate_type=1 AND t.aggregate_id=b.taskrun_id
                  AND t.current_version IN (b.claim_version,b.claim_version+1)
             JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
                  AND d.call_id=a.call_id AND d.provider_idempotency_key=a.provider_idempotency_key
                  AND d.fencing_token=a.fencing_token AND d.profile_digest=a.profile_digest
                  AND d.prepared_digest=a.prepared_digest AND d.render_digest=a.render_digest
             JOIN provider_accounting_settlements s ON s.dispatch_attempt_id=d.attempt_id
                  AND s.settlement_digest=d.settlement_digest
             LEFT JOIN provider_terminal_dispositions m ON m.dispatch_attempt_id=d.attempt_id
             WHERE o.state='active' AND o.dispatch_intent='present' AND d.state=5
               AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x WHERE x.dispatch_attempt_id=d.attempt_id)
               AND NOT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts x WHERE x.taskrun_id=b.taskrun_id)
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
                    let node = failure_fixed::<16>(row.get(4)?)?;
                    let principal_id: String = row.get(8)?;
                    let conversation_id = ConversationId::from_bytes(failure_fixed(row.get(2)?)?);
                    Ok(ProviderFailureRecoveryRecord {
                        kind: ProviderFailureRecoveryKind::SettledRemoteFailure,
                        pre_effect_rejection: None,
                        dispatch_attempt_id: failure_fixed(row.get(0)?)?,
                        taskrun_id,
                        conversation_id,
                        execution_attempt_id: attempt_id,
                        assignment: TaskRunAssignmentIdentity {
                            taskrun_id,
                            attempt_id,
                            node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
                            node_epoch: failure_positive(row.get(5)?)?,
                            fence: TaskRunFence(failure_positive(row.get(6)?)?),
                        },
                        claim_version: failure_positive(row.get(7)?)?,
                        principal_id,
                        submitted_prompt: String::new(),
                        workspace_id: None,
                        submit_actor: None,
                        runtime_generation: failure_positive(row.get(9)?)?,
                        provider_fencing_token: failure_positive(row.get(10)?)?,
                        profile_digest: failure_fixed(row.get(11)?)?,
                        pricing_revision_digest: failure_fixed(row.get(12)?)?,
                        settlement_digest: failure_fixed(row.get(13)?)?,
                        input_tokens: failure_nonnegative(row.get(14)?)?,
                        output_tokens: failure_nonnegative(row.get(15)?)?,
                        cached_input_tokens: failure_nonnegative(row.get(16)?)?,
                        reasoning_output_tokens: failure_nonnegative(row.get(17)?)?,
                        charge_micros: failure_nonnegative(row.get(18)?)?,
                        currency: row.get(19)?,
                        cancellation_taskrun_version: row
                            .get::<_, Option<i64>>(20)?
                            .map(failure_positive)
                            .transpose()?,
                        terminal_disposition: match row.get::<_, Option<i64>>(21)? {
                            None => None,
                            Some(1) => Some(ProviderTerminalDisposition::Completed),
                            Some(2) => Some(ProviderTerminalDisposition::RemoteFailed),
                            Some(3) => Some(ProviderTerminalDisposition::RemoteIncomplete),
                            Some(4) => Some(ProviderTerminalDisposition::CancelledUncertain),
                            Some(_) => return Err(rusqlite::Error::InvalidQuery),
                        },
                    })
                },
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let mut candidates = Vec::new();
        for row in rows {
            candidates.push(row.map_err(|_| storage_failure(StorageFailureKind::CorruptData))?);
        }
        let next_cursor = candidates
            .last()
            .map(|candidate| candidate.dispatch_attempt_id);
        let reached_end = candidates.len() < limit;
        let mut seen = std::collections::HashSet::new();
        if candidates
            .iter()
            .any(|candidate| !seen.insert(candidate.dispatch_attempt_id))
        {
            return Err(storage_failure(StorageFailureKind::CorruptData));
        }
        drop(statement);
        drop(reader);
        let mut validated = Vec::new();
        for mut candidate in candidates {
            if let Some((prompt, workspace, actor)) = validate_submitter(self, &candidate)? {
                candidate.submitted_prompt = prompt;
                candidate.workspace_id = Some(workspace);
                candidate.submit_actor = Some(actor);
                validated.push(candidate);
            }
        }
        Ok(ProviderFailureRecoveryPage {
            candidates: validated,
            next_cursor,
            reached_end,
        })
    }
}

fn failure_fixed<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
fn failure_positive(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}
fn failure_nonnegative(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn validate_submitter(
    store: &StoreTransaction,
    candidate: &ProviderFailureRecoveryRecord,
) -> Result<Option<(String, WorkspaceId, Actor)>, CommitError> {
    let stream = store
        .load_task_run(candidate.taskrun_id)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if stream.current_version != candidate.claim_version
        && stream.current_version != candidate.claim_version.saturating_add(1)
    {
        return Ok(None);
    }
    if candidate
        .cancellation_taskrun_version
        .is_some_and(|version| {
            version != stream.current_version
                || stream
                    .events
                    .last()
                    .is_none_or(|event| event.payload() != &TaskRunEvent::CancellationRequested)
        })
    {
        return Ok(None);
    }
    validate_submitter_identity(
        store,
        candidate.taskrun_id,
        candidate.conversation_id,
        &candidate.principal_id,
    )
}

pub(super) fn validate_submitter_identity(
    store: &StoreTransaction,
    taskrun_id: TaskRunId,
    conversation_id: ConversationId,
    principal_id: &str,
) -> Result<Option<(String, WorkspaceId, Actor)>, CommitError> {
    let stream = store
        .load_task_run(taskrun_id)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !matches!(
        stream.events.first().map(|event| event.payload()),
        Some(TaskRunEvent::TaskRunSubmitted { .. })
    ) {
        return Ok(None);
    }
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
    let origin = super::taskrun_submit_origin::verify_submitted_v2_origin(
        &reader,
        taskrun_id,
        &store.runtime_authority_id,
    )?
    .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if origin.conversation_id != conversation_id || origin.principal_id.0 != principal_id {
        return Ok(None);
    }
    Ok(Some((
        origin.input.prompt().to_owned(),
        origin.workspace_id,
        origin.actor,
    )))
}
