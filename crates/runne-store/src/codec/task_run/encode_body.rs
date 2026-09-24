{
        let mut buf = Vec::new();
        write_u16_be(&mut buf, Self::CODEC_VERSION);

        match value {
            TaskRunEvent::TaskRunSubmitted { conversation_id, workspace_id, input } => {
                buf.push(TAG_TASK_RUN_SUBMITTED);
                write_uuid(&mut buf, conversation_id.as_bytes());
                write_uuid(&mut buf, workspace_id.as_bytes());
                let prompt = input.prompt().as_bytes();
                buf.extend_from_slice(&(prompt.len() as u32).to_be_bytes());
                buf.extend_from_slice(prompt);
            }
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
            TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id,
                sequence,
                parent_cycle_id,
            } => {
                buf.push(TAG_LOOP_CYCLE_STARTED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_u64_be(&mut buf, *sequence);
                match parent_cycle_id {
                    None => buf.push(0),
                    Some(parent) => {
                        buf.push(1);
                        write_uuid(&mut buf, parent.as_bytes());
                    }
                }
            }
            TaskRunEvent::ContextCommitted {
                cycle_id,
                manifest_ref,
            } => {
                buf.push(TAG_CONTEXT_COMMITTED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                encode_context_ref(&mut buf, manifest_ref)?;
            }
            TaskRunEvent::PlanCommitted {
                cycle_id,
                plan_revision_ref,
                input_digest,
                output_digest,
                expected_proposal_indexes,
            } => {
                buf.push(TAG_PLAN_COMMITTED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                encode_plan_ref(&mut buf, plan_revision_ref)?;
                write_digest(&mut buf, input_digest);
                write_digest(&mut buf, output_digest);
                write_u32_vec(&mut buf, expected_proposal_indexes)?;
            }
            TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome } => {
                buf.push(TAG_STEP_OUTCOME_RECORDED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                encode_step_record(&mut buf, outcome)?;
            }
            TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition,
            } => {
                buf.push(TAG_LOOP_CYCLE_COMPLETED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                encode_disposition(&mut buf, disposition)?;
            }
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id,
                successor_cycle_id,
                attempt_id,
                sequence,
            } => {
                buf.push(TAG_NEXT_CYCLE_CREATED);
                write_uuid(&mut buf, parent_cycle_id.as_bytes());
                write_uuid(&mut buf, successor_cycle_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_u64_be(&mut buf, *sequence);
            }
            TaskRunEvent::RetryScheduled {
                ordinal,
                old_attempt_id,
                new_attempt_id,
                abandoned_cycle_id,
                step_outcome_ref,
                retry_policy_digest,
                budget_reservation_ref,
                delay_ms,
                due_at_unix_us,
            } => {
                buf.push(TAG_RETRY_SCHEDULED);
                write_u64_be(&mut buf, *ordinal);
                write_uuid(&mut buf, old_attempt_id.as_bytes());
                write_uuid(&mut buf, new_attempt_id.as_bytes());
                write_uuid(&mut buf, abandoned_cycle_id.as_bytes());
                encode_step_ref(&mut buf, step_outcome_ref);
                write_digest(&mut buf, retry_policy_digest);
                encode_budget_ref(&mut buf, budget_reservation_ref);
                write_u64_be(&mut buf, *delay_ms);
                write_i64_be(&mut buf, *due_at_unix_us);
            }
            TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal,
                attempt_id,
                activated_at_unix_us,
            } => {
                buf.push(TAG_ACTIVATE_SCHEDULED_RETRY_ATTEMPT);
                write_u64_be(&mut buf, *ordinal);
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_i64_be(&mut buf, *activated_at_unix_us);
            }
            TaskRunEvent::RecoveryResumeStarted {
                new_attempt_id,
                new_generation,
                abandoned_cycle_id,
                context_manifest_ref,
                checkpoint_ref,
                reconciliation_ref,
            } => {
                buf.push(TAG_RECOVERY_RESUME_STARTED);
                write_uuid(&mut buf, new_attempt_id.as_bytes());
                write_u64_be(&mut buf, *new_generation);
                match abandoned_cycle_id {
                    None => buf.push(0),
                    Some(cycle_id) => {
                        buf.push(1);
                        write_uuid(&mut buf, cycle_id.as_bytes());
                    }
                }
                encode_context_ref(&mut buf, context_manifest_ref)?;
                encode_checkpoint_ref(&mut buf, checkpoint_ref);
                encode_reconciliation_ref(&mut buf, reconciliation_ref);
            }
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                buf.push(TAG_LOOP_CHECKPOINT_STARTED);
                write_uuid(&mut buf, checkpoint_id.as_bytes());
                write_u64_be(&mut buf, *event_position);
                write_digest(&mut buf, integrity_digest);
            }
            TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id,
                event_position,
                body,
                integrity_digest,
            } => {
                buf.push(TAG_LOOP_CHECKPOINT_RECORDED);
                write_uuid(&mut buf, checkpoint_id.as_bytes());
                write_u64_be(&mut buf, *event_position);
                encode_checkpoint_body(&mut buf, body)?;
                write_digest(&mut buf, integrity_digest);
            }
            TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                buf.push(TAG_LOOP_CHECKPOINT_COMMITTED);
                write_uuid(&mut buf, checkpoint_id.as_bytes());
                write_u64_be(&mut buf, *event_position);
                write_digest(&mut buf, integrity_digest);
            }
            TaskRunEvent::LoopWakeAccepted {
                cycle_id,
                wake_evidence_ref,
            } => {
                buf.push(TAG_LOOP_WAKE_ACCEPTED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                encode_wake_evidence(&mut buf, wake_evidence_ref)?;
            }
        }
        Ok(buf)
}
