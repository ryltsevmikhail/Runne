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
                let reason = String::from_utf8(reason_bytes.to_vec()).map_err(|_| {
                    StoreCodecError::UnknownTag {
                        tag,
                        context: "TaskRunFailed reason (invalid UTF-8)",
                    }
                })?;
                TaskRunEvent::TaskRunFailed { reason }
            }
            TAG_BUDGET_EXHAUSTED => TaskRunEvent::BudgetExhausted,
            TAG_POLICY_DENIED => TaskRunEvent::PolicyDenied,
            TAG_RECONCILIATION_STARTED => TaskRunEvent::ReconciliationStarted,
            TAG_RECONCILED => TaskRunEvent::Reconciled,
            TAG_UNRECOVERABLE => TaskRunEvent::Unrecoverable,
            TAG_TASK_RUN_CANCELLED => TaskRunEvent::TaskRunCancelled,
            TAG_LOOP_CYCLE_STARTED => {
                let cycle_id = CycleId::from_bytes(read_uuid(bytes, &mut pos)?);
                let attempt_id = AttemptId::from_bytes(read_uuid(bytes, &mut pos)?);
                let sequence = read_u64_be(bytes, &mut pos)?;
                let parent_cycle_id = match *bytes.get(pos).ok_or(StoreCodecError::Truncated)? {
                    0 => {
                        pos += 1;
                        None
                    }
                    1 => {
                        pos += 1;
                        Some(CycleId::from_bytes(read_uuid(bytes, &mut pos)?))
                    }
                    tag => {
                        return Err(StoreCodecError::UnknownTag {
                            tag,
                            context: "LoopCycleStarted parent",
                        });
                    }
                };
                TaskRunEvent::LoopCycleStarted {
                    cycle_id,
                    attempt_id,
                    sequence,
                    parent_cycle_id,
                }
            }
            TAG_CONTEXT_COMMITTED => TaskRunEvent::ContextCommitted {
                cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                manifest_ref: decode_context_ref(bytes, &mut pos)?,
            },
            TAG_PLAN_COMMITTED => {
                let cycle_id = CycleId::from_bytes(read_uuid(bytes, &mut pos)?);
                let plan_revision_ref = decode_plan_ref(bytes, &mut pos)?;
                let input_digest = read_digest(bytes, &mut pos)?;
                let output_digest = read_digest(bytes, &mut pos)?;
                let expected_proposal_indexes = read_u32_vec(bytes, &mut pos)?;
                if expected_proposal_indexes
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                    || expected_proposal_indexes != plan_revision_ref.expected_proposal_indexes
                {
                    return Err(StoreCodecError::UnknownTag {
                        tag,
                        context: "PlanCommitted proposal indexes",
                    });
                }
                TaskRunEvent::PlanCommitted {
                    cycle_id,
                    plan_revision_ref,
                    input_digest,
                    output_digest,
                    expected_proposal_indexes,
                }
            }
            TAG_STEP_OUTCOME_RECORDED => TaskRunEvent::StepOutcomeRecorded {
                cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                outcome: decode_step_record(bytes, &mut pos)?,
            },
            TAG_LOOP_CYCLE_COMPLETED => TaskRunEvent::LoopCycleCompleted {
                cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                disposition: decode_disposition(bytes, &mut pos)?,
            },
            TAG_NEXT_CYCLE_CREATED => TaskRunEvent::NextCycleCreated {
                parent_cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                successor_cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                sequence: read_u64_be(bytes, &mut pos)?,
            },
            TAG_RETRY_SCHEDULED => TaskRunEvent::RetryScheduled {
                ordinal: read_u64_be(bytes, &mut pos)?,
                old_attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                new_attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                abandoned_cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                step_outcome_ref: decode_step_ref(bytes, &mut pos)?,
                retry_policy_digest: read_digest(bytes, &mut pos)?,
                budget_reservation_ref: decode_budget_ref(bytes, &mut pos)?,
                delay_ms: read_u64_be(bytes, &mut pos)?,
                due_at_unix_us: read_i64_be(bytes, &mut pos)?,
            },
            TAG_ACTIVATE_SCHEDULED_RETRY_ATTEMPT => TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal: read_u64_be(bytes, &mut pos)?,
                attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                activated_at_unix_us: read_i64_be(bytes, &mut pos)?,
            },
            TAG_RECOVERY_RESUME_STARTED => {
                let new_attempt_id = AttemptId::from_bytes(read_uuid(bytes, &mut pos)?);
                let new_generation = read_u64_be(bytes, &mut pos)?;
                let abandoned_cycle_id = match *bytes.get(pos).ok_or(StoreCodecError::Truncated)? {
                    0 => {
                        pos += 1;
                        None
                    }
                    1 => {
                        pos += 1;
                        Some(CycleId::from_bytes(read_uuid(bytes, &mut pos)?))
                    }
                    tag => {
                        return Err(StoreCodecError::UnknownTag {
                            tag,
                            context: "RecoveryResumeStarted abandoned cycle",
                        });
                    }
                };
                TaskRunEvent::RecoveryResumeStarted {
                    new_attempt_id,
                    new_generation,
                    abandoned_cycle_id,
                    context_manifest_ref: decode_context_ref(bytes, &mut pos)?,
                    checkpoint_ref: decode_checkpoint_ref(bytes, &mut pos)?,
                    reconciliation_ref: decode_reconciliation_ref(bytes, &mut pos)?,
                }
            }
            TAG_LOOP_CHECKPOINT_STARTED => TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, &mut pos)?),
                event_position: read_u64_be(bytes, &mut pos)?,
                integrity_digest: read_digest(bytes, &mut pos)?,
            },
            TAG_LOOP_CHECKPOINT_RECORDED => TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, &mut pos)?),
                event_position: read_u64_be(bytes, &mut pos)?,
                body: decode_checkpoint_body(bytes, &mut pos)?,
                integrity_digest: read_digest(bytes, &mut pos)?,
            },
            TAG_LOOP_CHECKPOINT_COMMITTED => TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, &mut pos)?),
                event_position: read_u64_be(bytes, &mut pos)?,
                integrity_digest: read_digest(bytes, &mut pos)?,
            },
            TAG_LOOP_WAKE_ACCEPTED => TaskRunEvent::LoopWakeAccepted {
                cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                wake_evidence_ref: decode_wake_evidence(bytes, &mut pos)?,
            },
            _ => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "TaskRunEvent",
                });
            }
        };

        if pos < bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - pos,
            });
        }

        Ok(event)
}
