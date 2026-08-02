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
            AggregateScope::NewConversation {
                conversation_id,
                workspace_id,
            } => {
                buf.push(0x02);
                write_uuid(&mut buf, conversation_id.as_bytes());
                write_uuid(&mut buf, workspace_id.as_bytes());
            }
            AggregateScope::ExistingConversation { conversation_id } => {
                buf.push(0x03);
                write_uuid(&mut buf, conversation_id.as_bytes());
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
            6 => OperationTag::CreateConversation,
            7 => OperationTag::StartLoopCycle,
            8 => OperationTag::CommitContext,
            9 => OperationTag::CommitPlan,
            10 => OperationTag::RecordStepOutcome,
            11 => OperationTag::CompleteLoopCycle,
            12 => OperationTag::CreateNextCycle,
            13 => OperationTag::ScheduleRetry,
            14 => OperationTag::ActivateScheduledRetryAttempt,
            15 => OperationTag::CommitRecoveryResume,
            16 => OperationTag::CommitLoopCheckpoint,
            17 => OperationTag::ResumeLoopWait,
            18 => OperationTag::GenerateConversationText,
            t => {
                return Err(StoreCodecError::UnknownTag {
                    tag: t,
                    context: "OperationTag",
                });
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
            0x02 => {
                let conversation_id = ConversationId::from_bytes(read_uuid(bytes, &mut pos)?);
                let workspace_id = WorkspaceId::from_bytes(read_uuid(bytes, &mut pos)?);
                AggregateScope::NewConversation {
                    conversation_id,
                    workspace_id,
                }
            }
            0x03 => AggregateScope::ExistingConversation {
                conversation_id: ConversationId::from_bytes(read_uuid(bytes, &mut pos)?),
            },
            t => {
                return Err(StoreCodecError::UnknownTag {
                    tag: t,
                    context: "AggregateScope",
                });
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
