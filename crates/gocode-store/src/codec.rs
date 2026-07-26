//! Durable codec — encodes and decodes domain types for SQLite BLOB storage.
//!
//! Each codec implements [`StoreCodec`] with a versioned encoding format.
//! Decoding must reject: unknown tags, trailing bytes, oversized values,
//! and unsupported codec versions.

use core::fmt;

use gocode_application::commands::CommandOutcome;
use gocode_application::ports::{AggregateScope, IdempotencyScope, OperationTag};
use gocode_domain::command::TerminalResult;
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId, WorkspaceId};
use gocode_domain::task_run::TaskRunEvent;

/// Error from a codec encode/decode operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreCodecError {
    /// Unsupported codec version.
    UnsupportedVersion {
        /// The version found in the encoded bytes.
        found: u16,
        /// The version this codec supports.
        supported: u16,
    },
    /// Unknown event tag in the encoded bytes.
    UnknownTag {
        /// The tag byte that was not recognized.
        tag: u8,
        /// Context for debugging (e.g., "TaskRunEvent").
        context: &'static str,
    },
    /// Not enough bytes to decode the value.
    Truncated,
    /// Extra bytes remaining after decoding.
    TrailingBytes {
        /// The number of extra bytes remaining.
        remaining: usize,
    },
    /// A value exceeds its maximum allowed size.
    Oversized {
        /// What was oversized.
        field: &'static str,
        /// The maximum allowed size.
        max: usize,
        /// The actual size.
        actual: usize,
    },
}

impl fmt::Display for StoreCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found, supported } => {
                write!(
                    f,
                    "unsupported codec version: found {}, supported {}",
                    found, supported
                )
            }
            Self::UnknownTag { tag, context } => {
                write!(f, "unknown tag 0x{:02x} in {}", tag, context)
            }
            Self::Truncated => write!(f, "truncated bytes"),
            Self::TrailingBytes { remaining } => {
                write!(f, "trailing bytes after decode: {}", remaining)
            }
            Self::Oversized { field, max, actual } => {
                write!(
                    f,
                    "{} exceeds max size: max={}, actual={}",
                    field, max, actual
                )
            }
        }
    }
}

impl std::error::Error for StoreCodecError {}

/// Trait for durable encoding/decoding of a type to/from BLOB bytes.
pub trait StoreCodec<T: Sized> {
    /// The codec version (incremented when encoding changes).
    const CODEC_VERSION: u16;

    /// Encode a value to bytes.
    fn encode(&self, value: &T) -> Result<Vec<u8>, StoreCodecError>;

    /// Decode bytes back into a value.
    fn decode(&self, bytes: &[u8]) -> Result<T, StoreCodecError>;
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Write a u16 in big-endian to a Vec.
fn write_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Write a u64 in big-endian to a Vec.
fn write_u64_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Write a length-prefixed byte slice (u16 BE length).
fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u16;
    write_u16_be(buf, len);
    buf.extend_from_slice(data);
}

/// Write raw UUID bytes (16 bytes).
fn write_uuid(buf: &mut Vec<u8>, bytes: &[u8; 16]) {
    buf.extend_from_slice(bytes);
}

/// Read a u16 BE from bytes at `pos`, advancing `pos`.
fn read_u16_be(bytes: &[u8], pos: &mut usize) -> Result<u16, StoreCodecError> {
    if *pos + 2 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let v = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

/// Read a u64 BE from bytes at `pos`, advancing `pos`.
fn read_u64_be(bytes: &[u8], pos: &mut usize) -> Result<u64, StoreCodecError> {
    if *pos + 8 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let v = u64::from_be_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
        bytes[*pos + 4],
        bytes[*pos + 5],
        bytes[*pos + 6],
        bytes[*pos + 7],
    ]);
    *pos += 8;
    Ok(v)
}

/// Read 16 bytes as a UUID from `pos`, advancing `pos`.
fn read_uuid(bytes: &[u8], pos: &mut usize) -> Result<[u8; 16], StoreCodecError> {
    if *pos + 16 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[*pos..*pos + 16]);
    *pos += 16;
    Ok(out)
}

/// Read a length-prefixed byte slice (u16 BE length), advancing `pos`.
fn read_len_prefixed<'a>(
    bytes: &'a [u8],
    pos: &mut usize,
) -> Result<&'a [u8], StoreCodecError> {
    let len = read_u16_be(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let data = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(data)
}

// ── TaskRunEvent codec ───────────────────────────────────────────────────

/// Event tag constants for TaskRunEvent encoding.
const TAG_TASK_RUN_CREATED: u8 = 0x01;
const TAG_TASK_RUN_QUEUED: u8 = 0x02;
const TAG_TASK_RUN_ADMITTED: u8 = 0x03;
const TAG_ATTEMPT_STARTED: u8 = 0x04;
const TAG_WAIT_STARTED: u8 = 0x05;
const TAG_RESUMED: u8 = 0x06;
const TAG_RETRY_STARTED: u8 = 0x07;
const TAG_RETRY_COMPLETED: u8 = 0x08;
const TAG_CHECKPOINT_STARTED: u8 = 0x09;
const TAG_CHECKPOINT_COMMITTED: u8 = 0x0A;
const TAG_CANCELLATION_REQUESTED: u8 = 0x0B;
const TAG_CANCELLATION_COMPLETED: u8 = 0x0C;
const TAG_TASK_RUN_COMPLETED: u8 = 0x0D;
const TAG_TASK_RUN_FAILED: u8 = 0x0E;
const TAG_BUDGET_EXHAUSTED: u8 = 0x0F;
const TAG_POLICY_DENIED: u8 = 0x10;
const TAG_RECONCILIATION_STARTED: u8 = 0x11;
const TAG_RECONCILED: u8 = 0x12;
const TAG_UNRECOVERABLE: u8 = 0x13;
const TAG_TASK_RUN_CANCELLED: u8 = 0x14;

/// Codec for [`TaskRunEvent`] payload BLOB.
pub struct TaskRunEventCodec;

impl StoreCodec<TaskRunEvent> for TaskRunEventCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &TaskRunEvent) -> Result<Vec<u8>, StoreCodecError> {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, Self::CODEC_VERSION);

        match value {
            TaskRunEvent::TaskRunCreated => {
                buf.push(TAG_TASK_RUN_CREATED);
            }
            TaskRunEvent::TaskRunQueued => {
                buf.push(TAG_TASK_RUN_QUEUED);
            }
            TaskRunEvent::TaskRunAdmitted => {
                buf.push(TAG_TASK_RUN_ADMITTED);
            }
            TaskRunEvent::AttemptStarted { attempt_id } => {
                buf.push(TAG_ATTEMPT_STARTED);
                write_uuid(&mut buf, attempt_id.as_bytes());
            }
            TaskRunEvent::WaitStarted => {
                buf.push(TAG_WAIT_STARTED);
            }
            TaskRunEvent::Resumed => {
                buf.push(TAG_RESUMED);
            }
            TaskRunEvent::RetryStarted { attempt_id } => {
                buf.push(TAG_RETRY_STARTED);
                write_uuid(&mut buf, attempt_id.as_bytes());
            }
            TaskRunEvent::RetryCompleted { attempt_id } => {
                buf.push(TAG_RETRY_COMPLETED);
                write_uuid(&mut buf, attempt_id.as_bytes());
            }
            TaskRunEvent::CheckpointStarted => {
                buf.push(TAG_CHECKPOINT_STARTED);
            }
            TaskRunEvent::CheckpointCommitted => {
                buf.push(TAG_CHECKPOINT_COMMITTED);
            }
            TaskRunEvent::CancellationRequested => {
                buf.push(TAG_CANCELLATION_REQUESTED);
            }
            TaskRunEvent::CancellationCompleted => {
                buf.push(TAG_CANCELLATION_COMPLETED);
            }
            TaskRunEvent::TaskRunCompleted { result } => {
                buf.push(TAG_TASK_RUN_COMPLETED);
                encode_terminal_result(&mut buf, result);
            }
            TaskRunEvent::TaskRunFailed { reason } => {
                buf.push(TAG_TASK_RUN_FAILED);
                write_len_prefixed(&mut buf, reason.as_bytes());
            }
            TaskRunEvent::BudgetExhausted => {
                buf.push(TAG_BUDGET_EXHAUSTED);
            }
            TaskRunEvent::PolicyDenied => {
                buf.push(TAG_POLICY_DENIED);
            }
            TaskRunEvent::ReconciliationStarted => {
                buf.push(TAG_RECONCILIATION_STARTED);
            }
            TaskRunEvent::Reconciled => {
                buf.push(TAG_RECONCILED);
            }
            TaskRunEvent::Unrecoverable => {
                buf.push(TAG_UNRECOVERABLE);
            }
            TaskRunEvent::TaskRunCancelled => {
                buf.push(TAG_TASK_RUN_CANCELLED);
            }
        }
        Ok(buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<TaskRunEvent, StoreCodecError> {
        let mut pos = 0usize;
        let version = read_u16_be(bytes, &mut pos)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        if pos >= bytes.len() {
            return Err(StoreCodecError::Truncated);
        }
        let tag = bytes[pos];
        pos += 1;

        let event = match tag {
            TAG_TASK_RUN_CREATED => TaskRunEvent::TaskRunCreated,
            TAG_TASK_RUN_QUEUED => TaskRunEvent::TaskRunQueued,
            TAG_TASK_RUN_ADMITTED => TaskRunEvent::TaskRunAdmitted,
            TAG_ATTEMPT_STARTED => {
                let aid = read_uuid(bytes, &mut pos)?;
                TaskRunEvent::AttemptStarted {
                    attempt_id: AttemptId::from_bytes(aid),
                }
            }
            TAG_WAIT_STARTED => TaskRunEvent::WaitStarted,
            TAG_RESUMED => TaskRunEvent::Resumed,
            TAG_RETRY_STARTED => {
                let aid = read_uuid(bytes, &mut pos)?;
                TaskRunEvent::RetryStarted {
                    attempt_id: AttemptId::from_bytes(aid),
                }
            }
            TAG_RETRY_COMPLETED => {
                let aid = read_uuid(bytes, &mut pos)?;
                TaskRunEvent::RetryCompleted {
                    attempt_id: AttemptId::from_bytes(aid),
                }
            }
            TAG_CHECKPOINT_STARTED => TaskRunEvent::CheckpointStarted,
            TAG_CHECKPOINT_COMMITTED => TaskRunEvent::CheckpointCommitted,
            TAG_CANCELLATION_REQUESTED => TaskRunEvent::CancellationRequested,
            TAG_CANCELLATION_COMPLETED => TaskRunEvent::CancellationCompleted,
            TAG_TASK_RUN_COMPLETED => {
                let result = decode_terminal_result(bytes, &mut pos)?;
                TaskRunEvent::TaskRunCompleted { result }
            }
            TAG_TASK_RUN_FAILED => {
                let reason_bytes = read_len_prefixed(bytes, &mut pos)?;
                let reason =
                    String::from_utf8(reason_bytes.to_vec()).map_err(|_| StoreCodecError::UnknownTag {
                        tag,
                        context: "TaskRunFailed reason (invalid UTF-8)",
                    })?;
                TaskRunEvent::TaskRunFailed { reason }
            }
            TAG_BUDGET_EXHAUSTED => TaskRunEvent::BudgetExhausted,
            TAG_POLICY_DENIED => TaskRunEvent::PolicyDenied,
            TAG_RECONCILIATION_STARTED => TaskRunEvent::ReconciliationStarted,
            TAG_RECONCILED => TaskRunEvent::Reconciled,
            TAG_UNRECOVERABLE => TaskRunEvent::Unrecoverable,
            TAG_TASK_RUN_CANCELLED => TaskRunEvent::TaskRunCancelled,
            _ => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "TaskRunEvent",
                })
            }
        };

        if pos < bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - pos,
            });
        }

        Ok(event)
    }
}

/// Encode a [`TerminalResult`] into a buffer.
fn encode_terminal_result(buf: &mut Vec<u8>, result: &TerminalResult) {
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
fn decode_terminal_result(
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
            let reason =
                String::from_utf8(reason_bytes.to_vec()).map_err(|_| StoreCodecError::UnknownTag {
                    tag: 0x01,
                    context: "TerminalResult::Failure reason (invalid UTF-8)",
                })?;
            Ok(TerminalResult::Failure { reason })
        }
        tag => Err(StoreCodecError::UnknownTag {
            tag,
            context: "TerminalResult",
        }),
    }
}

// ── CommandOutcome codec ─────────────────────────────────────────────────

const CO_TAG_CREATED: u8 = 0x01;
const CO_TAG_QUEUED: u8 = 0x02;
const CO_TAG_ADMITTED: u8 = 0x03;
const CO_TAG_ATTEMPT_STARTED: u8 = 0x04;
const CO_TAG_COMPLETED: u8 = 0x05;

/// Codec for [`CommandOutcome`] receipt BLOB.
pub struct CommandOutcomeCodec;

impl StoreCodec<CommandOutcome> for CommandOutcomeCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &CommandOutcome) -> Result<Vec<u8>, StoreCodecError> {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, Self::CODEC_VERSION);

        match value {
            CommandOutcome::TaskRunCreated {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_CREATED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::TaskRunQueued {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_QUEUED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::TaskRunAdmitted {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_ADMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::AttemptStarted {
                taskrun_id,
                attempt_id,
                new_version,
            } => {
                buf.push(CO_TAG_ATTEMPT_STARTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::TaskRunCompleted {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_COMPLETED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
        }
        Ok(buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<CommandOutcome, StoreCodecError> {
        let mut pos = 0usize;
        let version = read_u16_be(bytes, &mut pos)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        if pos >= bytes.len() {
            return Err(StoreCodecError::Truncated);
        }
        let tag = bytes[pos];
        pos += 1;

        let outcome = match tag {
            CO_TAG_CREATED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunCreated {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_QUEUED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunQueued {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_ADMITTED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunAdmitted {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_ATTEMPT_STARTED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let att_id = AttemptId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::AttemptStarted {
                    taskrun_id: tr_id,
                    attempt_id: att_id,
                    new_version: nv,
                }
            }
            CO_TAG_COMPLETED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunCompleted {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            _ => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "CommandOutcome",
                })
            }
        };

        if pos < bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - pos,
            });
        }

        Ok(outcome)
    }
}

// ── IdempotencyScope codec ───────────────────────────────────────────────

/// Codec for [`IdempotencyScope`] — stored in `command_receipts`.
pub struct IdempotencyScopeCodec;

impl StoreCodec<IdempotencyScope> for IdempotencyScopeCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &IdempotencyScope) -> Result<Vec<u8>, StoreCodecError> {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, Self::CODEC_VERSION);

        // runtime_authority_id (length-prefixed ASCII)
        let ra_bytes = value.runtime_authority_id.0.as_bytes();
        write_len_prefixed(&mut buf, ra_bytes);

        // principal_id (length-prefixed ASCII)
        let p_bytes = value.principal_id.0.as_bytes();
        write_len_prefixed(&mut buf, p_bytes);

        // operation (u8)
        buf.push(value.operation as u8);

        // aggregate_scope
        match &value.aggregate_scope {
            AggregateScope::NewTaskRun {
                conversation_id,
                workspace_id,
            } => {
                buf.push(0x00); // tag: NewTaskRun
                write_uuid(&mut buf, conversation_id.as_bytes());
                write_uuid(&mut buf, workspace_id.as_bytes());
            }
            AggregateScope::ExistingTaskRun { taskrun_id } => {
                buf.push(0x01); // tag: ExistingTaskRun
                write_uuid(&mut buf, taskrun_id.as_bytes());
            }
        }

        Ok(buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<IdempotencyScope, StoreCodecError> {
        let mut pos = 0usize;
        let version = read_u16_be(bytes, &mut pos)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }

        let ra_bytes = read_len_prefixed(bytes, &mut pos)?;
        let runtime_authority_id = gocode_application::ports::RuntimeAuthorityId(
            String::from_utf8(ra_bytes.to_vec()).map_err(|_| StoreCodecError::UnknownTag {
                tag: 0,
                context: "RuntimeAuthorityId (invalid UTF-8)",
            })?,
        );

        let p_bytes = read_len_prefixed(bytes, &mut pos)?;
        let principal_id = gocode_application::ports::PrincipalId(
            String::from_utf8(p_bytes.to_vec()).map_err(|_| StoreCodecError::UnknownTag {
                tag: 0,
                context: "PrincipalId (invalid UTF-8)",
            })?,
        );

        if pos >= bytes.len() {
            return Err(StoreCodecError::Truncated);
        }
        let op_tag = bytes[pos];
        pos += 1;
        let operation = match op_tag {
            1 => OperationTag::CreateTaskRun,
            2 => OperationTag::Queue,
            3 => OperationTag::Admit,
            4 => OperationTag::StartAttempt,
            5 => OperationTag::Complete,
            t => {
                return Err(StoreCodecError::UnknownTag {
                    tag: t,
                    context: "OperationTag",
                })
            }
        };

        if pos >= bytes.len() {
            return Err(StoreCodecError::Truncated);
        }
        let scope_tag = bytes[pos];
        pos += 1;
        let aggregate_scope = match scope_tag {
            0x00 => {
                let conv_bytes = read_uuid(bytes, &mut pos)?;
                let ws_bytes = read_uuid(bytes, &mut pos)?;
                AggregateScope::NewTaskRun {
                    conversation_id: ConversationId::from_bytes(conv_bytes),
                    workspace_id: WorkspaceId::from_bytes(ws_bytes),
                }
            }
            0x01 => {
                let tr_bytes = read_uuid(bytes, &mut pos)?;
                AggregateScope::ExistingTaskRun {
                    taskrun_id: TaskRunId::from_bytes(tr_bytes),
                }
            }
            t => {
                return Err(StoreCodecError::UnknownTag {
                    tag: t,
                    context: "AggregateScope",
                })
            }
        };

        if pos < bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - pos,
            });
        }

        Ok(IdempotencyScope {
            runtime_authority_id,
            principal_id,
            operation,
            aggregate_scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TR_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
    const ATT_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
    const CONV_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
    const WS_ID: &str = "018f2e3a-7000-7000-8000-000000000004";

    // ── TaskRunEvent round-trip ────────────────────────────────────────

    #[test]
    fn test_taskrun_event_codec_roundtrip_created() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCreated;
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_queued() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunQueued;
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_attempt_started() {
        let codec = TaskRunEventCodec;
        let aid: AttemptId = ATT_ID.parse().unwrap();
        let original = TaskRunEvent::AttemptStarted { attempt_id: aid };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_completed_success() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_completed_failure() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Failure {
                reason: "test error".into(),
            },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_rejects_unknown_version() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        // Corrupt version bytes
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(
            err,
            StoreCodecError::UnsupportedVersion { .. }
        ));
    }

    #[test]
    fn test_taskrun_event_codec_rejects_unknown_tag() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        bytes[2] = 0xFF;
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(err, StoreCodecError::UnknownTag { .. }));
    }

    #[test]
    fn test_taskrun_event_codec_rejects_trailing_bytes() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        bytes.push(0x00);
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(err, StoreCodecError::TrailingBytes { .. }));
    }

    // ── CommandOutcome round-trip ──────────────────────────────────────

    #[test]
    fn test_command_outcome_codec_roundtrip_created() {
        let codec = CommandOutcomeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let original = CommandOutcome::TaskRunCreated {
            taskrun_id: tr_id,
            new_version: 1,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_command_outcome_codec_roundtrip_attempt_started() {
        let codec = CommandOutcomeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let att_id: AttemptId = ATT_ID.parse().unwrap();
        let original = CommandOutcome::AttemptStarted {
            taskrun_id: tr_id,
            attempt_id: att_id,
            new_version: 4,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    // ── IdempotencyScope round-trip ────────────────────────────────────

    #[test]
    fn test_idempotency_scope_codec_roundtrip_existing() {
        let codec = IdempotencyScopeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let original = IdempotencyScope {
            runtime_authority_id: gocode_application::ports::RuntimeAuthorityId("host-1".into()),
            principal_id: gocode_application::ports::PrincipalId("user-1".into()),
            operation: OperationTag::Queue,
            aggregate_scope: AggregateScope::ExistingTaskRun {
                taskrun_id: tr_id,
            },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_idempotency_scope_codec_roundtrip_new() {
        let codec = IdempotencyScopeCodec;
        let conv_id: ConversationId = CONV_ID.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID.parse().unwrap();
        let original = IdempotencyScope {
            runtime_authority_id: gocode_application::ports::RuntimeAuthorityId("host-1".into()),
            principal_id: gocode_application::ports::PrincipalId("user-1".into()),
            operation: OperationTag::CreateTaskRun,
            aggregate_scope: AggregateScope::NewTaskRun {
                conversation_id: conv_id,
                workspace_id: ws_id,
            },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }
}
