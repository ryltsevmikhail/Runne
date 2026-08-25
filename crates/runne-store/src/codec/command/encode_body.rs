{
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
            CommandOutcome::TaskRunCancellationRequested {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_CANCELLATION_REQUESTED);
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
            CommandOutcome::CycleStarted {
                taskrun_id,
                cycle_id,
                new_version,
            } => {
                buf.push(CO_TAG_CYCLE_STARTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::ContextCommitted {
                taskrun_id,
                cycle_id,
                new_version,
            } => {
                buf.push(CO_TAG_CONTEXT_COMMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::PlanCommitted {
                taskrun_id,
                plan_ref,
                new_version,
            } => {
                buf.push(CO_TAG_PLAN_COMMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                encode_plan_ref(&mut buf, plan_ref.as_ref())?;
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::StepOutcomeRecorded {
                taskrun_id,
                step_id,
                new_version,
            } => {
                buf.push(CO_TAG_STEP_OUTCOME_RECORDED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, step_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::LoopDispositionCommitted {
                taskrun_id,
                cycle_id,
                final_state,
                new_version,
            } => {
                buf.push(CO_TAG_LOOP_DISPOSITION_COMMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, cycle_id.as_bytes());
                buf.push(encode_taskrun_state(*final_state));
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::NextCycleAllocated {
                taskrun_id,
                successor_cycle_id,
                new_version,
            } => {
                buf.push(CO_TAG_NEXT_CYCLE_ALLOCATED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, successor_cycle_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::LoopWaitResumed {
                taskrun_id,
                cycle_id,
                new_version,
            } => {
                buf.push(CO_TAG_LOOP_WAIT_RESUMED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::RetryScheduled {
                taskrun_id,
                new_attempt_id,
                due_at_unix_us,
                new_version,
            } => {
                buf.push(CO_TAG_RETRY_SCHEDULED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, new_attempt_id.as_bytes());
                write_i64_be(&mut buf, *due_at_unix_us);
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::RetryActivated {
                taskrun_id,
                attempt_id,
                new_version,
            }
            | CommandOutcome::RecoveryResumed {
                taskrun_id,
                attempt_id,
                new_version,
            } => {
                buf.push(if matches!(value, CommandOutcome::RetryActivated { .. }) {
                    CO_TAG_RETRY_ACTIVATED
                } else {
                    CO_TAG_RECOVERY_RESUMED
                });
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::LoopCheckpointCommitted {
                taskrun_id,
                checkpoint_id,
                event_position,
                new_version,
            } => {
                buf.push(CO_TAG_LOOP_CHECKPOINT_COMMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, checkpoint_id.as_bytes());
                write_u64_be(&mut buf, *event_position);
                write_u64_be(&mut buf, *new_version);
            }
        }
        Ok(buf)
}
