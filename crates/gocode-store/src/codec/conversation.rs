use super::primitives::*;
use super::*;

// ── ConversationEvent codec ──────────────────────────────────────────────

pub(super) const TAG_CONVERSATION_CREATED: u8 = 0x20;
pub(super) const TAG_CONVERSATION_CLOSED: u8 = 0x21;
pub(super) const TAG_USER_MESSAGE_APPENDED: u8 = 0x22;
pub(super) const TAG_ASSISTANT_MESSAGE_APPENDED: u8 = 0x23;
pub(super) const TAG_GENERATION_FAILED: u8 = 0x24;
pub(super) const REASON_PROVIDER_OUTPUT_REJECTED: u8 = 0x00;

/// Codec for [`ConversationEvent`] payload BLOBs.
pub struct ConversationEventCodec;

impl StoreCodec<ConversationEvent> for ConversationEventCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &ConversationEvent) -> Result<Vec<u8>, StoreCodecError> {
        let mut buffer = Vec::with_capacity(67);
        write_u16_be(&mut buffer, Self::CODEC_VERSION);
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
                });
            }
        }
        Ok(buffer)
    }

    fn decode(&self, bytes: &[u8]) -> Result<ConversationEvent, StoreCodecError> {
        let mut position = 0;
        let version = read_u16_be(bytes, &mut position)?;
        if version != Self::CODEC_VERSION {
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
