use super::*;
use runne_application::ports::{ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence};

#[derive(Debug, Clone)]
pub struct D2CompletionRecoveryCandidate {
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub cycle_id: runne_domain::id::CycleId,
    pub conversation_id: ConversationId,
    pub principal_id: String,
    pub assignment: TaskRunAssignmentIdentity,
    pub original_claim_version: u64,
    pub taskrun_head: u64,
    pub terminal_attempt_id: [u8; 16],
    pub terminal_outbox_id: [u8; 16],
    pub terminal_sequence: u64,
    pub settlement_digest: IntegrityDigest,
    pub fencing_token: u64,
    pub call_digest_version: runne_provider::ProviderCallDigestVersion,
    pub profile_digest: [u8; 32],
    pub runtime_generation: u64,
    pub terminal_sources: Vec<runne_application::ports::D2ToolTerminalSourceV1>,
}

#[derive(Debug, Clone)]
pub struct D2CompletionRecoveryPage {
    pub candidates: Vec<D2CompletionRecoveryCandidate>,
    pub reached_end: bool,
}

impl StoreTransaction {
    pub fn d2_completion_recovery_candidates(
        &self,
        after: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<D2CompletionRecoveryPage, CommitError> {
        use crate::store::parse_helpers::storage_failure;
        if limit == 0 || limit > 64 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let mut statement = reader.prepare(
            "SELECT r.taskrun_id,r.attempt_id,i.cycle_id,a.conversation_id,a.principal_id,
                    r.node_id,r.node_epoch,r.fence,r.original_claim_version,t.current_version,
                    o.dispatch_attempt_id,o.outbox_id,o.terminal_sequence,o.settlement_digest,
                    d.fencing_token,r.call_digest_version,r.profile_digest,a.generation
             FROM taskrun_provider_round_bindings r
             JOIN taskrun_tool_invocations i ON i.taskrun_id=r.taskrun_id AND i.attempt_id=r.attempt_id
                  AND i.proposal_index=0 AND i.state='result' AND i.result_truncated=0
                  AND i.local_stop_state=2 AND i.managed_area_identity=i.empty_proof_identity
             JOIN taskrun_tool_invocations j ON j.taskrun_id=i.taskrun_id AND j.attempt_id=i.attempt_id
                  AND j.cycle_id=i.cycle_id AND j.proposal_index=1 AND j.state='result'
                  AND j.result_truncated=0 AND j.local_stop_state=2
                  AND j.managed_area_identity=j.empty_proof_identity
             JOIN provider_execution_admissions a ON a.provider_idempotency_key=r.provider_idempotency_key
                  AND a.taskrun_id=r.taskrun_id AND a.execution_attempt_id=r.attempt_id
             JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
             JOIN provider_terminal_outbox o ON o.dispatch_attempt_id=d.attempt_id
                  AND o.profile_digest=r.profile_digest AND o.runtime_generation=a.generation
                  AND o.call_digest_version=r.call_digest_version
             JOIN provider_terminal_application_kinds k ON k.dispatch_attempt_id=o.dispatch_attempt_id
                  AND k.outbox_id=o.outbox_id AND k.application_kind=2
             JOIN aggregate_streams t ON t.aggregate_type=1 AND t.aggregate_id=r.taskrun_id
             WHERE r.round_index=2 AND r.previous_attempt_id=r.attempt_id
               AND r.previous_cycle_id=i.cycle_id AND r.previous_proposal_index=1
               AND r.previous_semantic_digest=j.semantic_digest AND r.previous_result_digest=j.result_digest
               AND r.profile_digest=a.profile_digest AND (?1 IS NULL OR r.taskrun_id>?1)
               AND NOT EXISTS(SELECT 1 FROM d2_tool_loop_completions c WHERE c.taskrun_id=r.taskrun_id)
             ORDER BY r.taskrun_id LIMIT ?2",
        ).map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let rows = statement
            .query_map(
                rusqlite::params![after.as_ref().map(|id| id.as_slice()), limit as i64],
                |row| {
                    let taskrun_id = TaskRunId::from_bytes(fixed16(row.get(0)?)?);
                    let attempt_id = AttemptId::from_bytes(fixed16(row.get(1)?)?);
                    let node = fixed16(row.get(5)?)?;
                    let digest_version = match row.get::<_, i64>(15)? {
                        1 => runne_provider::ProviderCallDigestVersion::V1,
                        2 => runne_provider::ProviderCallDigestVersion::V2,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    Ok(D2CompletionRecoveryCandidate {
                        taskrun_id,
                        attempt_id,
                        cycle_id: runne_domain::id::CycleId::from_bytes(fixed16(row.get(2)?)?),
                        conversation_id: ConversationId::from_bytes(fixed16(row.get(3)?)?),
                        principal_id: row.get(4)?,
                        assignment: TaskRunAssignmentIdentity {
                            taskrun_id,
                            attempt_id,
                            node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
                            node_epoch: positive(row.get(6)?)?,
                            fence: TaskRunFence(positive(row.get(7)?)?),
                        },
                        original_claim_version: positive(row.get(8)?)?,
                        taskrun_head: positive(row.get(9)?)?,
                        terminal_attempt_id: fixed16(row.get(10)?)?,
                        terminal_outbox_id: fixed16(row.get(11)?)?,
                        terminal_sequence: nonnegative(row.get(12)?)?,
                        settlement_digest: IntegrityDigest::from_bytes(fixed32(row.get(13)?)?),
                        fencing_token: positive(row.get(14)?)?,
                        call_digest_version: digest_version,
                        profile_digest: fixed32(row.get(16)?)?,
                        runtime_generation: positive(row.get(17)?)?,
                        terminal_sources: Vec::new(),
                    })
                },
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let mut candidates = Vec::new();
        for row in rows {
            let mut candidate =
                row.map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            candidate.terminal_sources = terminal_sources(&reader, &candidate)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            candidates.push(candidate);
        }
        let reached_end = candidates.len() < limit;
        drop(statement);
        drop(reader);
        Ok(D2CompletionRecoveryPage {
            candidates,
            reached_end,
        })
    }
}

fn terminal_sources(
    reader: &rusqlite::Connection,
    candidate: &D2CompletionRecoveryCandidate,
) -> Result<Vec<runne_application::ports::D2ToolTerminalSourceV1>, rusqlite::Error> {
    let mut statement = reader.prepare(
        "SELECT sequence,event_kind,terminal,plaintext_digest,profile_digest,runtime_generation
         FROM provider_stream_journal WHERE dispatch_attempt_id=?1 AND
          ((event_kind=7 AND terminal=0) OR (event_kind=5 AND terminal=1 AND sequence=?2))
         ORDER BY sequence",
    )?;
    let rows = statement.query_map(
        rusqlite::params![
            candidate.terminal_attempt_id.as_slice(),
            candidate.terminal_sequence as i64
        ],
        |row| {
            Ok(runne_application::ports::D2ToolTerminalSourceV1 {
                dispatch_attempt_id: candidate.terminal_attempt_id,
                sequence: nonnegative(row.get(0)?)?,
                event_kind: u8::try_from(row.get::<_, i64>(1)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                terminal: row.get::<_, i64>(2)? == 1,
                plaintext_digest: IntegrityDigest::from_bytes(fixed32(row.get(3)?)?),
                profile_digest: IntegrityDigest::from_bytes(fixed32(row.get(4)?)?),
                runtime_generation: positive(row.get(5)?)?,
            })
        },
    )?;
    let mut sources = rows.collect::<Result<Vec<_>, _>>()?;
    if sources.is_empty()
        || sources.len() > 32
        || sources
            .iter()
            .filter(|source| source.event_kind == 5 && source.terminal)
            .count()
            != 1
        || sources.iter().any(|source| {
            !((source.event_kind == 7 && !source.terminal)
                || (source.event_kind == 5 && source.terminal))
        })
        || sources.iter().any(|source| {
            source.profile_digest.as_bytes() != &candidate.profile_digest
                || source.runtime_generation != candidate.runtime_generation
        })
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    sources.sort_by_key(|source| source.sequence);
    if !sources
        .windows(2)
        .all(|pair| pair[0].sequence < pair[1].sequence)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(sources)
}

fn fixed16(value: Vec<u8>) -> Result<[u8; 16], rusqlite::Error> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
fn fixed32(value: Vec<u8>) -> Result<[u8; 32], rusqlite::Error> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
fn positive(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}
fn nonnegative(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}
