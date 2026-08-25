use super::primitives::*;
use super::refs::*;
use super::*;

/// Encode a [`TerminalResult`] into a buffer.
pub(super) fn encode_terminal_result(buf: &mut Vec<u8>, result: &TerminalResult) {
    match result {
        TerminalResult::Success => {
            buf.push(0x00);
        }
        TerminalResult::Failure { reason } => {
            buf.push(0x01);
            write_len_prefixed(buf, reason.as_bytes());
        }
    }
}

/// Decode a [`TerminalResult`] from bytes at `pos`.
pub(super) fn decode_terminal_result(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<TerminalResult, StoreCodecError> {
    if *pos >= bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let tag = bytes[*pos];
    *pos += 1;
    match tag {
        0x00 => Ok(TerminalResult::Success),
        0x01 => {
            let reason_bytes = read_len_prefixed(bytes, pos)?;
            let reason = String::from_utf8(reason_bytes.to_vec()).map_err(|_| {
                StoreCodecError::UnknownTag {
                    tag: 0x01,
                    context: "TerminalResult::Failure reason (invalid UTF-8)",
                }
            })?;
            Ok(TerminalResult::Failure { reason })
        }
        tag => Err(StoreCodecError::UnknownTag {
            tag,
            context: "TerminalResult",
        }),
    }
}

fn encode_taskrun_state(state: TaskRunState) -> u8 {
    match state {
        TaskRunState::Created => 0,
        TaskRunState::Queued => 1,
        TaskRunState::Admitted => 2,
        TaskRunState::Running => 3,
        TaskRunState::Waiting => 4,
        TaskRunState::Retrying => 5,
        TaskRunState::Checkpointing => 6,
        TaskRunState::Cancelling => 7,
        TaskRunState::Reconciling => 8,
        TaskRunState::Succeeded => 9,
        TaskRunState::Failed => 10,
        TaskRunState::Cancelled => 11,
        TaskRunState::BudgetExhausted => 12,
        TaskRunState::PolicyDenied => 13,
        TaskRunState::Unrecoverable => 14,
    }
}

fn decode_taskrun_state(bytes: &[u8], pos: &mut usize) -> Result<TaskRunState, StoreCodecError> {
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    match tag {
        0 => Ok(TaskRunState::Created),
        1 => Ok(TaskRunState::Queued),
        2 => Ok(TaskRunState::Admitted),
        3 => Ok(TaskRunState::Running),
        4 => Ok(TaskRunState::Waiting),
        5 => Ok(TaskRunState::Retrying),
        6 => Ok(TaskRunState::Checkpointing),
        7 => Ok(TaskRunState::Cancelling),
        8 => Ok(TaskRunState::Reconciling),
        9 => Ok(TaskRunState::Succeeded),
        10 => Ok(TaskRunState::Failed),
        11 => Ok(TaskRunState::Cancelled),
        12 => Ok(TaskRunState::BudgetExhausted),
        13 => Ok(TaskRunState::PolicyDenied),
        14 => Ok(TaskRunState::Unrecoverable),
        tag => Err(StoreCodecError::UnknownTag {
            tag,
            context: "TaskRunState",
        }),
    }
}

// ── CommandOutcome codec ─────────────────────────────────────────────────

pub(super) const CO_TAG_CREATED: u8 = 0x01;
pub(super) const CO_TAG_QUEUED: u8 = 0x02;
pub(super) const CO_TAG_ADMITTED: u8 = 0x03;
pub(super) const CO_TAG_ATTEMPT_STARTED: u8 = 0x04;
pub(super) const CO_TAG_COMPLETED: u8 = 0x05;
pub(super) const CO_TAG_CYCLE_STARTED: u8 = 0x06;
pub(super) const CO_TAG_CONTEXT_COMMITTED: u8 = 0x07;
pub(super) const CO_TAG_PLAN_COMMITTED: u8 = 0x08;
pub(super) const CO_TAG_STEP_OUTCOME_RECORDED: u8 = 0x09;
pub(super) const CO_TAG_LOOP_DISPOSITION_COMMITTED: u8 = 0x0A;
pub(super) const CO_TAG_NEXT_CYCLE_ALLOCATED: u8 = 0x0B;
pub(super) const CO_TAG_LOOP_WAIT_RESUMED: u8 = 0x0C;
pub(super) const CO_TAG_RETRY_SCHEDULED: u8 = 0x0D;
pub(super) const CO_TAG_RETRY_ACTIVATED: u8 = 0x0E;
pub(super) const CO_TAG_RECOVERY_RESUMED: u8 = 0x0F;
pub(super) const CO_TAG_LOOP_CHECKPOINT_COMMITTED: u8 = 0x10;
pub(super) const CO_TAG_CANCELLATION_REQUESTED: u8 = 0x11;

/// Codec for [`CommandOutcome`] receipt BLOB.
pub struct CommandOutcomeCodec;

impl StoreCodec<CommandOutcome> for CommandOutcomeCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &CommandOutcome) -> Result<Vec<u8>, StoreCodecError> {
        include!("command/encode_body.rs")
    }

    fn decode(&self, bytes: &[u8]) -> Result<CommandOutcome, StoreCodecError> {
        include!("command/decode_body.rs")
    }
}
