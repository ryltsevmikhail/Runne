use super::*;
use runne_application::ports::{AggregateScope, OperationTag, TextGenerationPhase};
use runne_domain::{agent_loop::StepOutcomeType, task_run::TaskRunState};
use sha2::{Digest, Sha256};

const D2_FAILURE: &str = "D2 tool approval or effect did not complete safely";
type GenerationIdentity = (Vec<u8>, Vec<u8>, String, Vec<u8>);

pub(super) struct PreviousResult<'a> {
    pub(super) attempt_id: &'a [u8],
    pub(super) cycle_id: &'a [u8],
    pub(super) proposal_index: u32,
    pub(super) semantic_digest: &'a [u8],
    pub(super) result_digest: &'a [u8],
}

pub(super) struct SemanticFields<'a> {
    pub(super) principal: &'a str,
    pub(super) conversation: &'a [u8],
    pub(super) taskrun: &'a [u8],
    pub(super) attempt: &'a [u8],
    pub(super) call: &'a [u8],
    pub(super) digest_version: u8,
    pub(super) prepared: &'a [u8],
    pub(super) render: &'a [u8],
    pub(super) profile: &'a [u8],
    pub(super) pricing: &'a [u8],
    pub(super) input_tokens: u64,
    pub(super) output_tokens: u64,
    pub(super) max_cost: u64,
    pub(super) currency: &'a str,
    pub(super) idempotency_key: &'a str,
}

pub(super) fn semantic_digest(fields: &SemanticFields<'_>) -> Option<[u8; 32]> {
    if [
        fields.conversation,
        fields.taskrun,
        fields.attempt,
        fields.call,
    ]
    .iter()
    .any(|bytes| bytes.len() != 16)
        || [
            fields.prepared,
            fields.render,
            fields.profile,
            fields.pricing,
        ]
        .iter()
        .any(|bytes| bytes.len() != 32)
        || !matches!(fields.digest_version, 1 | 2)
    {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(b"GOCODE_PROVIDER_EXECUTION_SEMANTIC_V1\0");
    hash_text(&mut hash, fields.principal);
    hash.update(fields.conversation);
    hash.update(fields.taskrun);
    hash.update(fields.attempt);
    hash.update(fields.call);
    hash.update([fields.digest_version]);
    hash.update(fields.prepared);
    hash.update(fields.render);
    hash.update(fields.profile);
    hash.update(fields.pricing);
    hash.update(fields.input_tokens.to_be_bytes());
    hash.update(fields.output_tokens.to_be_bytes());
    hash.update(fields.max_cost.to_be_bytes());
    hash_text(&mut hash, fields.currency);
    hash_text(&mut hash, fields.idempotency_key);
    Some(hash.finalize().into())
}

fn hash_text(hash: &mut Sha256, text: &str) {
    hash.update((text.len() as u64).to_be_bytes());
    hash.update(text.as_bytes());
}

pub(super) fn durable_generation_identity(
    connection: &rusqlite::Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    current_head: u64,
    original_claim_version: u64,
) -> Result<GenerationIdentity, CommitError> {
    let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        connection,
        taskrun_id,
        Some(current_head),
    )
    .map_err(|_| integrity())?;
    let task = TaskRun::replay(&stream.events).map_err(|_| integrity())?;
    let first = stream.events.first().ok_or_else(integrity)?;
    let (conversation, workspace) = match first.payload() {
        TaskRunEvent::TaskRunSubmitted {
            conversation_id,
            workspace_id,
            ..
        } => (*conversation_id, *workspace_id),
        _ => return Err(integrity()),
    };
    let mut statement = connection.prepare(
        "SELECT command_id,payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1 ORDER BY sequence",
    ).map_err(|_| integrity())?;
    let rows = statement
        .query_map([conversation.as_bytes()], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|_| integrity())?;
    let mut generation_source = None;
    for row in rows {
        let (command, payload) = row.map_err(|_| integrity())?;
        if let ConversationEvent::UserMessageAppended {
            message_id,
            taskrun_id: owner,
            attempt_id: active_attempt,
            ..
        } = ConversationEventCodec
            .decode(&payload)
            .map_err(|_| integrity())?
            && owner == taskrun_id
            && active_attempt == attempt_id
            && generation_source.replace((command, message_id)).is_some()
        {
            return Err(integrity());
        }
    }
    let (command, user_message) = generation_source.ok_or_else(integrity)?;
    let (scope_bytes, receipt_bytes): (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT idempotency_scope_bytes,command_outcome FROM command_receipts WHERE command_id=?1",
        [command.as_slice()], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(|_| integrity())?;
    let scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| integrity())?;
    let receipt = TextGenerationReceiptCodec
        .decode(&receipt_bytes)
        .map_err(|_| integrity())?;
    let phase_matches = match task.state() {
        TaskRunState::Running => {
            task.active_attempt() == Some(&attempt_id)
                && receipt.phase == TextGenerationPhase::Started
                && receipt.taskrun_version == original_claim_version
        }
        TaskRunState::Failed => {
            (receipt.phase == TextGenerationPhase::Started
                && receipt.taskrun_version == original_claim_version)
                || (receipt.phase == TextGenerationPhase::Rejected
                    && receipt.taskrun_version == current_head)
        }
        _ => false,
    };
    if scope.operation != OperationTag::GenerateConversationText
        || !matches!(scope.aggregate_scope, AggregateScope::ExistingConversation { conversation_id } if conversation_id == conversation)
        || !phase_matches
        || receipt.conversation_id != conversation
        || receipt.workspace_id != workspace
        || receipt.taskrun_id != taskrun_id
        || receipt.attempt_id != attempt_id
        || receipt.user_message_id != user_message
    {
        return Err(integrity());
    }
    let authority = uuid::Uuid::parse_str(&scope.runtime_authority_id.0)
        .map_err(|_| integrity())?
        .as_bytes()
        .to_vec();
    Ok((
        command,
        conversation.as_bytes().to_vec(),
        scope.principal_id.0,
        authority,
    ))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the proof binds both legal stream suffixes to the exact previous invocation result"
)]
pub(super) fn validate_failure_suffix(
    connection: &rusqlite::Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    version: u64,
    original_claim_version: u64,
    expected_cycle: &[u8],
    proposal: i64,
    result_digest: &[u8],
) -> Result<(Vec<u8>, u64), CommitError> {
    let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        connection,
        taskrun_id,
        Some(version),
    )
    .map_err(|_| integrity())?;
    let task = TaskRun::replay(&stream.events).map_err(|_| integrity())?;
    if task.state() == TaskRunState::Running && task.active_attempt() == Some(&attempt_id) {
        let last = stream.events.last().ok_or_else(integrity)?;
        let (cycle, outcome) = match last.payload() {
            TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome } => (*cycle_id, outcome),
            _ => return Err(integrity()),
        };
        if cycle.as_bytes() != expected_cycle
            || !matches_previous_step(outcome, proposal, result_digest)
            || last.sequence() != version
            || version <= original_claim_version
        {
            return Err(integrity());
        }
        return Ok((cycle.as_bytes().to_vec(), version));
    }
    if task.state() != TaskRunState::Failed || stream.events.len() < 3 {
        return Err(integrity());
    }
    let n = stream.events.len();
    let cycle = match stream.events[n - 2].payload() {
        TaskRunEvent::LoopCycleCompleted {
            cycle_id,
            attempt_id: event_attempt,
            disposition: runne_domain::agent_loop::LoopDisposition::Fail { reason, .. },
        } if *event_attempt == attempt_id && reason == D2_FAILURE => *cycle_id,
        _ => return Err(integrity()),
    };
    if cycle.as_bytes() != expected_cycle
        || !matches!(stream.events[n-1].payload(), TaskRunEvent::TaskRunFailed { reason } if reason==D2_FAILURE)
    {
        return Err(integrity());
    }
    let (step_cycle, outcome) = match stream.events[n - 3].payload() {
        TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome } => (*cycle_id, outcome),
        _ => return Err(integrity()),
    };
    if step_cycle != cycle
        || !matches_previous_step(outcome, proposal, result_digest)
        || stream.events[n - 3].sequence() != version.checked_sub(2).ok_or_else(integrity)?
        || version
            .checked_sub(2)
            .is_none_or(|head| head <= original_claim_version)
    {
        return Err(integrity());
    }
    Ok((cycle.as_bytes().to_vec(), stream.events[n - 3].sequence()))
}

fn matches_previous_step(
    outcome: &runne_domain::agent_loop::StepOutcomeRecord,
    proposal: i64,
    result_digest: &[u8],
) -> bool {
    u32::try_from(proposal).ok() == Some(outcome.proposal_index)
        && outcome.outcome_type == StepOutcomeType::Succeeded
        && outcome
            .result_ref
            .as_ref()
            .is_some_and(|result| result.integrity_digest().as_bytes().as_slice() == result_digest)
}

fn integrity() -> CommitError {
    super::integrity()
}

pub(super) fn round_call_id(
    command_id: &[u8],
    taskrun_id: &[u8],
    attempt_id: &[u8],
    taskrun_head: u64,
    round_index: u32,
    previous: PreviousResult<'_>,
) -> Option<[u8; 16]> {
    if [
        command_id,
        taskrun_id,
        attempt_id,
        previous.attempt_id,
        previous.cycle_id,
    ]
    .iter()
    .any(|bytes| bytes.len() != 16)
        || previous.semantic_digest.len() != 32
        || previous.result_digest.len() != 32
    {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(b"RUNNE_D2_PROVIDER_ROUND_CALL_V1\0");
    hash.update(command_id);
    hash.update(taskrun_id);
    hash.update(attempt_id);
    hash.update(taskrun_head.to_be_bytes());
    hash.update(round_index.to_be_bytes());
    hash.update(previous.attempt_id);
    hash.update(previous.cycle_id);
    hash.update(previous.proposal_index.to_be_bytes());
    hash.update(previous.semantic_digest);
    hash.update(previous.result_digest);
    hash.finalize()[..16].try_into().ok()
}
