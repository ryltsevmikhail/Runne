use super::primitives::*;
use super::*;

// ── ConversationEvent codec ──────────────────────────────────────────────

pub(super) const TAG_CONVERSATION_CREATED: u8 = 0x20;
pub(super) const TAG_CONVERSATION_CLOSED: u8 = 0x21;
pub(super) const TAG_USER_MESSAGE_APPENDED: u8 = 0x22;
pub(super) const TAG_ASSISTANT_MESSAGE_APPENDED: u8 = 0x23;
pub(super) const TAG_GENERATION_FAILED: u8 = 0x24;
pub(super) const TAG_GENERATION_SUPERSEDED_UNKNOWN: u8 = 0x25;
pub(super) const REASON_PROVIDER_OUTPUT_REJECTED: u8 = 0x00;
pub(super) const REASON_INTERRUPTED_BY_RESTART: u8 = 0x01;
pub(super) const REASON_PROVIDER_EXECUTION_REJECTED: u8 = 0x02;
pub(super) const REASON_PROVIDER_EXECUTION_FAILED: u8 = 0x03;
pub(super) const REASON_CANCELLED: u8 = 0x04;
pub(super) const REASON_PROVIDER_ACCOUNTING_UNKNOWN: u8 = 0x05;

/// Codec for [`ConversationEvent`] payload BLOBs.
pub struct ConversationEventCodec;

impl StoreCodec<ConversationEvent> for ConversationEventCodec {
    const CODEC_VERSION: u16 = 2;

    fn encode(&self, value: &ConversationEvent) -> Result<Vec<u8>, StoreCodecError> {
        let mut buffer = Vec::with_capacity(67);
        let version = if matches!(
            value,
            ConversationEvent::GenerationSupersededUnknown { .. }
                | ConversationEvent::GenerationFailed {
                    reason: GenerationFailureReason::ProviderAccountingUnknown,
                    ..
                }
        ) {
            Self::CODEC_VERSION
        } else {
            1
        };
        write_u16_be(&mut buffer, version);
        match value {
            ConversationEvent::ConversationCreated { workspace_id } => {
                buffer.push(TAG_CONVERSATION_CREATED);
                write_uuid(&mut buffer, workspace_id.as_bytes());
            }
            ConversationEvent::ConversationClosed => buffer.push(TAG_CONVERSATION_CLOSED),
            ConversationEvent::UserMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => {
                buffer.push(TAG_USER_MESSAGE_APPENDED);
                encode_message_event(&mut buffer, *message_id, *taskrun_id, *attempt_id, text);
            }
            ConversationEvent::AssistantMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => {
                buffer.push(TAG_ASSISTANT_MESSAGE_APPENDED);
                encode_message_event(&mut buffer, *message_id, *taskrun_id, *attempt_id, text);
            }
            ConversationEvent::GenerationFailed {
                taskrun_id,
                attempt_id,
                reason,
            } => {
                buffer.push(TAG_GENERATION_FAILED);
                write_uuid(&mut buffer, taskrun_id.as_bytes());
                write_uuid(&mut buffer, attempt_id.as_bytes());
                buffer.push(match reason {
                    GenerationFailureReason::ProviderOutputRejected => {
                        REASON_PROVIDER_OUTPUT_REJECTED
                    }
                    GenerationFailureReason::InterruptedByRestart => REASON_INTERRUPTED_BY_RESTART,
                    GenerationFailureReason::ProviderExecutionRejected => {
                        REASON_PROVIDER_EXECUTION_REJECTED
                    }
                    GenerationFailureReason::ProviderExecutionFailed => {
                        REASON_PROVIDER_EXECUTION_FAILED
                    }
                    GenerationFailureReason::Cancelled => REASON_CANCELLED,
                    GenerationFailureReason::ProviderAccountingUnknown => {
                        REASON_PROVIDER_ACCOUNTING_UNKNOWN
                    }
                });
            }
            ConversationEvent::GenerationSupersededUnknown {
                taskrun_id,
                attempt_id,
                successor_taskrun_id,
                acknowledgement_digest,
            } => {
                buffer.push(TAG_GENERATION_SUPERSEDED_UNKNOWN);
                write_uuid(&mut buffer, taskrun_id.as_bytes());
                write_uuid(&mut buffer, attempt_id.as_bytes());
                write_uuid(&mut buffer, successor_taskrun_id.as_bytes());
                write_digest(&mut buffer, acknowledgement_digest);
            }
        }
        Ok(buffer)
    }

    fn decode(&self, bytes: &[u8]) -> Result<ConversationEvent, StoreCodecError> {
        let mut position = 0;
        let version = read_u16_be(bytes, &mut position)?;
        if !(1..=Self::CODEC_VERSION).contains(&version) {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        let tag = *bytes.get(position).ok_or(StoreCodecError::Truncated)?;
        position += 1;
        let event = match tag {
            TAG_CONVERSATION_CREATED => {
                let workspace_bytes = read_uuid(bytes, &mut position)?;
                let workspace_id = WorkspaceId::from_bytes(workspace_bytes);
                workspace_id
                    .to_string()
                    .parse::<WorkspaceId>()
                    .map_err(|_| StoreCodecError::UnknownTag {
                        tag,
                        context: "ConversationCreated workspace UUIDv7",
                    })?;
                ConversationEvent::ConversationCreated { workspace_id }
            }
            TAG_CONVERSATION_CLOSED => ConversationEvent::ConversationClosed,
            TAG_USER_MESSAGE_APPENDED => {
                let (message_id, taskrun_id, attempt_id, text) =
                    decode_message_event(bytes, &mut position)?;
                ConversationEvent::UserMessageAppended {
                    message_id,
                    taskrun_id,
                    attempt_id,
                    text,
                }
            }
            TAG_ASSISTANT_MESSAGE_APPENDED => {
                let (message_id, taskrun_id, attempt_id, text) =
                    decode_message_event(bytes, &mut position)?;
                ConversationEvent::AssistantMessageAppended {
                    message_id,
                    taskrun_id,
                    attempt_id,
                    text,
                }
            }
            TAG_GENERATION_FAILED => {
                let taskrun_id =
                    parse_codec_uuid::<TaskRunId>(read_uuid(bytes, &mut position)?, "TaskRunId")?;
                let attempt_id =
                    parse_codec_uuid::<AttemptId>(read_uuid(bytes, &mut position)?, "AttemptId")?;
                let reason_tag = *bytes.get(position).ok_or(StoreCodecError::Truncated)?;
                position += 1;
                let reason = match reason_tag {
                    REASON_PROVIDER_OUTPUT_REJECTED => {
                        GenerationFailureReason::ProviderOutputRejected
                    }
                    REASON_INTERRUPTED_BY_RESTART => GenerationFailureReason::InterruptedByRestart,
                    REASON_PROVIDER_EXECUTION_REJECTED => {
                        GenerationFailureReason::ProviderExecutionRejected
                    }
                    REASON_PROVIDER_EXECUTION_FAILED => {
                        GenerationFailureReason::ProviderExecutionFailed
                    }
                    REASON_CANCELLED => GenerationFailureReason::Cancelled,
                    REASON_PROVIDER_ACCOUNTING_UNKNOWN if version >= 2 => {
                        GenerationFailureReason::ProviderAccountingUnknown
                    }
                    tag => {
                        return Err(StoreCodecError::UnknownTag {
                            tag,
                            context: "GenerationFailureReason",
                        });
                    }
                };
                ConversationEvent::GenerationFailed {
                    taskrun_id,
                    attempt_id,
                    reason,
                }
            }
            TAG_GENERATION_SUPERSEDED_UNKNOWN if version >= 2 => {
                let taskrun_id =
                    parse_codec_uuid::<TaskRunId>(read_uuid(bytes, &mut position)?, "TaskRunId")?;
                let attempt_id =
                    parse_codec_uuid::<AttemptId>(read_uuid(bytes, &mut position)?, "AttemptId")?;
                let successor_taskrun_id =
                    parse_codec_uuid::<TaskRunId>(read_uuid(bytes, &mut position)?, "TaskRunId")?;
                let acknowledgement_digest = read_digest(bytes, &mut position)?;
                ConversationEvent::GenerationSupersededUnknown {
                    taskrun_id,
                    attempt_id,
                    successor_taskrun_id,
                    acknowledgement_digest,
                }
            }
            _ => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "ConversationEvent",
                });
            }
        };
        if position != bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - position,
            });
        }
        Ok(event)
    }
}

fn encode_message_event(
    buffer: &mut Vec<u8>,
    message_id: MessageId,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    text: &MessageText,
) {
    write_uuid(buffer, message_id.as_bytes());
    write_uuid(buffer, taskrun_id.as_bytes());
    write_uuid(buffer, attempt_id.as_bytes());
    write_u64_be(buffer, text.as_str().len() as u64);
    buffer.extend_from_slice(text.as_str().as_bytes());
}

fn decode_message_event(
    bytes: &[u8],
    position: &mut usize,
) -> Result<(MessageId, TaskRunId, AttemptId, MessageText), StoreCodecError> {
    let message_id = parse_codec_uuid::<MessageId>(read_uuid(bytes, position)?, "MessageId")?;
    let taskrun_id = parse_codec_uuid::<TaskRunId>(read_uuid(bytes, position)?, "TaskRunId")?;
    let attempt_id = parse_codec_uuid::<AttemptId>(read_uuid(bytes, position)?, "AttemptId")?;
    let length =
        usize::try_from(read_u64_be(bytes, position)?).map_err(|_| StoreCodecError::Oversized {
            field: "message_text",
            max: MAX_MESSAGE_TEXT_BYTES,
            actual: usize::MAX,
        })?;
    if length > MAX_MESSAGE_TEXT_BYTES {
        return Err(StoreCodecError::Oversized {
            field: "message_text",
            max: MAX_MESSAGE_TEXT_BYTES,
            actual: length,
        });
    }
    let end = position
        .checked_add(length)
        .ok_or(StoreCodecError::Truncated)?;
    let text = bytes
        .get(*position..end)
        .ok_or(StoreCodecError::Truncated)?;
    *position = end;
    let text = String::from_utf8(text.to_vec()).map_err(|_| StoreCodecError::UnknownTag {
        tag: 0,
        context: "Conversation message UTF-8",
    })?;
    let text = MessageText::new(text).map_err(|_| StoreCodecError::Oversized {
        field: "message_text",
        max: MAX_MESSAGE_TEXT_BYTES,
        actual: length,
    })?;
    Ok((message_id, taskrun_id, attempt_id, text))
}
