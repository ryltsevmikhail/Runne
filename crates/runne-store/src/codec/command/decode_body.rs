{
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
            CO_TAG_SUBMITTED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunSubmitted {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_UNKNOWN_SUCCESSOR_CREATED => CommandOutcome::UnknownSuccessorCreated {
                predecessor_taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                predecessor_version: read_u64_be(bytes, &mut pos)?,
                conversation_id: ConversationId::from_bytes(read_uuid(bytes, &mut pos)?),
                conversation_version: read_u64_be(bytes, &mut pos)?,
                successor_taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                successor_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_CANCELLATION_REQUESTED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunCancellationRequested {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_CANCELLATION_COMPLETED => {
                let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let new_version = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunCancellationCompleted { taskrun_id, new_version }
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
            CO_TAG_CYCLE_STARTED | CO_TAG_CONTEXT_COMMITTED | CO_TAG_LOOP_WAIT_RESUMED => {
                let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let cycle_id = CycleId::from_bytes(read_uuid(bytes, &mut pos)?);
                let new_version = read_u64_be(bytes, &mut pos)?;
                match tag {
                    CO_TAG_CYCLE_STARTED => CommandOutcome::CycleStarted {
                        taskrun_id,
                        cycle_id,
                        new_version,
                    },
                    CO_TAG_CONTEXT_COMMITTED => CommandOutcome::ContextCommitted {
                        taskrun_id,
                        cycle_id,
                        new_version,
                    },
                    _ => CommandOutcome::LoopWaitResumed {
                        taskrun_id,
                        cycle_id,
                        new_version,
                    },
                }
            }
            CO_TAG_PLAN_COMMITTED => CommandOutcome::PlanCommitted {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                plan_ref: Box::new(decode_plan_ref(bytes, &mut pos)?),
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_STEP_OUTCOME_RECORDED => CommandOutcome::StepOutcomeRecorded {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                step_id: StepId::from_bytes(read_uuid(bytes, &mut pos)?),
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_LOOP_DISPOSITION_COMMITTED => {
                let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let cycle_id = CycleId::from_bytes(read_uuid(bytes, &mut pos)?);
                let final_state = decode_taskrun_state(bytes, &mut pos)?;
                CommandOutcome::LoopDispositionCommitted {
                    taskrun_id,
                    cycle_id,
                    final_state,
                    new_version: read_u64_be(bytes, &mut pos)?,
                }
            }
            CO_TAG_NEXT_CYCLE_ALLOCATED => CommandOutcome::NextCycleAllocated {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                successor_cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_RETRY_SCHEDULED => CommandOutcome::RetryScheduled {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                new_attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                due_at_unix_us: read_i64_be(bytes, &mut pos)?,
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_RETRY_ACTIVATED | CO_TAG_RECOVERY_RESUMED => {
                let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let attempt_id = AttemptId::from_bytes(read_uuid(bytes, &mut pos)?);
                let new_version = read_u64_be(bytes, &mut pos)?;
                if tag == CO_TAG_RETRY_ACTIVATED {
                    CommandOutcome::RetryActivated {
                        taskrun_id,
                        attempt_id,
                        new_version,
                    }
                } else {
                    CommandOutcome::RecoveryResumed {
                        taskrun_id,
                        attempt_id,
                        new_version,
                    }
                }
            }
            CO_TAG_LOOP_CHECKPOINT_COMMITTED => CommandOutcome::LoopCheckpointCommitted {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, &mut pos)?),
                event_position: read_u64_be(bytes, &mut pos)?,
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            _ => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "CommandOutcome",
                });
            }
        };

        if pos < bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - pos,
            });
        }

        Ok(outcome)
}
