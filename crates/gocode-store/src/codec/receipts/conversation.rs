// ── ConversationReceipt codec ────────────────────────────────────────────

/// Codec for durable create-conversation receipts.
pub struct ConversationReceiptCodec;

impl StoreCodec<ConversationReceipt> for ConversationReceiptCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &ConversationReceipt) -> Result<Vec<u8>, StoreCodecError> {
        let mut buffer = Vec::with_capacity(50);
        write_u16_be(&mut buffer, Self::CODEC_VERSION);
        write_uuid(&mut buffer, value.conversation_id.as_bytes());
        write_uuid(&mut buffer, value.workspace_id.as_bytes());
        write_u64_be(&mut buffer, value.new_version);
        write_i64_be(&mut buffer, value.committed_at.as_unix_micros());
        Ok(buffer)
    }

    fn decode(&self, bytes: &[u8]) -> Result<ConversationReceipt, StoreCodecError> {
        let mut position = 0;
        let version = read_u16_be(bytes, &mut position)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        let conversation_id = ConversationId::from_bytes(read_uuid(bytes, &mut position)?);
        let workspace_id = WorkspaceId::from_bytes(read_uuid(bytes, &mut position)?);
        conversation_id
            .to_string()
            .parse::<ConversationId>()
            .map_err(|_| StoreCodecError::UnknownTag {
                tag: 0,
                context: "ConversationReceipt conversation UUIDv7",
            })?;
        workspace_id
            .to_string()
            .parse::<WorkspaceId>()
            .map_err(|_| StoreCodecError::UnknownTag {
                tag: 0,
                context: "ConversationReceipt workspace UUIDv7",
            })?;
        let new_version = read_u64_be(bytes, &mut position)?;
        let committed_at = gocode_domain::timestamp::Timestamp::from_unix_micros(read_i64_be(
            bytes,
            &mut position,
        )?);
        if committed_at.as_unix_micros() < 0 {
            return Err(StoreCodecError::UnknownTag {
                tag: 0,
                context: "ConversationReceipt negative commit timestamp",
            });
        }
        if position != bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - position,
            });
        }
        Ok(ConversationReceipt {
            conversation_id,
            workspace_id,
            new_version,
            committed_at,
        })
    }
}

// ── TextGenerationReceipt codec ─────────────────────────────────────────

/// Codec for durable Conversation/TaskRun text coordination receipts.
pub struct TextGenerationReceiptCodec;

impl StoreCodec<TextGenerationReceipt> for TextGenerationReceiptCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &TextGenerationReceipt) -> Result<Vec<u8>, StoreCodecError> {
        let mut buffer = Vec::with_capacity(115);
        write_u16_be(&mut buffer, Self::CODEC_VERSION);
        buffer.push(match value.phase {
            TextGenerationPhase::Started => 0,
            TextGenerationPhase::Completed => 1,
            TextGenerationPhase::Rejected => 2,
            TextGenerationPhase::ProhibitedInputRejected => 3,
        });
        write_uuid(&mut buffer, value.conversation_id.as_bytes());
        write_uuid(&mut buffer, value.workspace_id.as_bytes());
        write_uuid(&mut buffer, value.taskrun_id.as_bytes());
        write_uuid(&mut buffer, value.attempt_id.as_bytes());
        write_uuid(&mut buffer, value.user_message_id.as_bytes());
        write_uuid(&mut buffer, value.assistant_message_id.as_bytes());
        write_u64_be(&mut buffer, value.conversation_version);
        write_u64_be(&mut buffer, value.taskrun_version);
        Ok(buffer)
    }

    fn decode(&self, bytes: &[u8]) -> Result<TextGenerationReceipt, StoreCodecError> {
        let mut position = 0;
        let version = read_u16_be(bytes, &mut position)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        let phase = match *bytes.get(position).ok_or(StoreCodecError::Truncated)? {
            0 => TextGenerationPhase::Started,
            1 => TextGenerationPhase::Completed,
            2 => TextGenerationPhase::Rejected,
            3 => TextGenerationPhase::ProhibitedInputRejected,
            tag => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "TextGenerationPhase",
                });
            }
        };
        position += 1;
        let receipt = TextGenerationReceipt {
            phase,
            conversation_id: parse_codec_uuid(
                read_uuid(bytes, &mut position)?,
                "TextGenerationReceipt ConversationId",
            )?,
            workspace_id: {
                let workspace_id = WorkspaceId::from_bytes(read_uuid(bytes, &mut position)?);
                workspace_id
                    .to_string()
                    .parse::<WorkspaceId>()
                    .map_err(|_| StoreCodecError::UnknownTag {
                        tag: 0,
                        context: "TextGenerationReceipt WorkspaceId",
                    })?
            },
            taskrun_id: parse_codec_uuid(
                read_uuid(bytes, &mut position)?,
                "TextGenerationReceipt TaskRunId",
            )?,
            attempt_id: parse_codec_uuid(
                read_uuid(bytes, &mut position)?,
                "TextGenerationReceipt AttemptId",
            )?,
            user_message_id: parse_codec_uuid(
                read_uuid(bytes, &mut position)?,
                "TextGenerationReceipt user MessageId",
            )?,
            assistant_message_id: parse_codec_uuid(
                read_uuid(bytes, &mut position)?,
                "TextGenerationReceipt assistant MessageId",
            )?,
            conversation_version: read_u64_be(bytes, &mut position)?,
            taskrun_version: read_u64_be(bytes, &mut position)?,
        };
        if position != bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - position,
            });
        }
        Ok(receipt)
    }
}
