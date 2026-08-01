/// Closed role spelling for canonical Conversation replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CanonicalMessageRoleV1 {
    /// Authenticated caller text.
    User,
    /// Bound assistant output.
    Assistant,
}

/// Stable failure while adapting a domain event to its bounded public payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalReplayPayloadError {
    /// A failure reason was empty or exceeded the public UTF-8 byte bound.
    InvalidFailureReason,
}

impl From<&ConversationEvent> for CanonicalReplayPayloadV1 {
    fn from(event: &ConversationEvent) -> Self {
        match event {
            ConversationEvent::ConversationCreated { workspace_id } => Self::ConversationCreated {
                workspace_id: workspace_id.to_string(),
            },
            ConversationEvent::UserMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => Self::ConversationMessageAppended {
                role: CanonicalMessageRoleV1::User,
                message_id: message_id.to_string(),
                task_run_id: taskrun_id.to_string(),
                attempt_id: attempt_id.to_string(),
                text: text.as_str().to_owned(),
            },
            ConversationEvent::AssistantMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => Self::ConversationMessageAppended {
                role: CanonicalMessageRoleV1::Assistant,
                message_id: message_id.to_string(),
                task_run_id: taskrun_id.to_string(),
                attempt_id: attempt_id.to_string(),
                text: text.as_str().to_owned(),
            },
            ConversationEvent::GenerationFailed {
                taskrun_id,
                attempt_id,
                reason,
            } => Self::ConversationGenerationFailed {
                task_run_id: taskrun_id.to_string(),
                attempt_id: attempt_id.to_string(),
                reason: generation_failure_reason(*reason).to_owned(),
            },
            ConversationEvent::ConversationClosed => Self::ConversationClosed,
        }
    }
}

impl TryFrom<&TaskRunEvent> for CanonicalReplayPayloadV1 {
    type Error = CanonicalReplayPayloadError;

    fn try_from(event: &TaskRunEvent) -> Result<Self, Self::Error> {
        Ok(match event {
            TaskRunEvent::TaskRunCreated => Self::TaskRunCreated,
            TaskRunEvent::TaskRunQueued => Self::TaskRunQueued,
            TaskRunEvent::TaskRunAdmitted => Self::TaskRunAdmitted,
            TaskRunEvent::AttemptStarted { attempt_id } => Self::TaskRunAttemptStarted {
                attempt_id: attempt_id.to_string(),
            },
            TaskRunEvent::WaitStarted => Self::TaskRunWaitStarted,
            TaskRunEvent::Resumed => Self::TaskRunResumed,
            TaskRunEvent::RetryStarted { attempt_id } => Self::TaskRunRetryStarted {
                attempt_id: attempt_id.to_string(),
            },
            TaskRunEvent::RetryCompleted { attempt_id } => Self::TaskRunRetryCompleted {
                attempt_id: attempt_id.to_string(),
            },
            TaskRunEvent::CheckpointStarted => Self::TaskRunCheckpointStarted,
            TaskRunEvent::CheckpointCommitted => Self::TaskRunCheckpointCommitted,
            TaskRunEvent::CancellationRequested => Self::TaskRunCancellationRequested,
            TaskRunEvent::CancellationCompleted => Self::TaskRunCancellationCompleted,
            TaskRunEvent::TaskRunCompleted { result } => {
                let (outcome, reason) = match result {
                    TerminalResult::Success => ("success", None),
                    TerminalResult::Failure { reason } => {
                        ("failure", Some(bounded_failure_reason(reason)?))
                    }
                };
                Self::TaskRunCompleted {
                    outcome: outcome.to_owned(),
                    reason,
                }
            }
            TaskRunEvent::TaskRunFailed { reason } => Self::TaskRunFailed {
                reason: bounded_failure_reason(reason)?,
            },
            TaskRunEvent::BudgetExhausted => Self::TaskRunBudgetExhausted,
            TaskRunEvent::PolicyDenied => Self::TaskRunPolicyDenied,
            TaskRunEvent::ReconciliationStarted => Self::TaskRunReconciliationStarted,
            TaskRunEvent::Reconciled => Self::TaskRunReconciliationCompleted,
            TaskRunEvent::Unrecoverable => Self::TaskRunUnrecoverable,
            TaskRunEvent::TaskRunCancelled => Self::TaskRunCancelled,
            TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id,
                sequence,
                parent_cycle_id,
            } => Self::TaskRunLoopCycleStarted {
                cycle_id: cycle_id.to_string(),
                attempt_id: attempt_id.to_string(),
                sequence: *sequence,
                parent_cycle_id: parent_cycle_id.map(|id| id.to_string()),
            },
            TaskRunEvent::ContextCommitted {
                cycle_id,
                manifest_ref,
            } => Self::TaskRunContextCommitted {
                cycle_id: cycle_id.to_string(),
                manifest_id: manifest_ref.manifest_id.to_string(),
                revision: manifest_ref.revision,
            },
            TaskRunEvent::PlanCommitted {
                cycle_id,
                plan_revision_ref,
                expected_proposal_indexes,
                ..
            } => Self::TaskRunPlanCommitted {
                cycle_id: cycle_id.to_string(),
                plan_id: plan_revision_ref.plan_id.to_string(),
                revision: plan_revision_ref.revision,
                expected_proposal_indexes: expected_proposal_indexes.clone(),
            },
            TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome } => {
                Self::TaskRunStepOutcomeRecorded {
                    cycle_id: cycle_id.to_string(),
                    proposal_index: outcome.proposal_index,
                    step_id: outcome.step_id.to_string(),
                    outcome: step_outcome_type(outcome.outcome_type).to_owned(),
                }
            }
            TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition,
            } => Self::TaskRunLoopCycleCompleted {
                cycle_id: cycle_id.to_string(),
                attempt_id: attempt_id.to_string(),
                disposition: loop_disposition(disposition).to_owned(),
            },
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id,
                successor_cycle_id,
                attempt_id,
                sequence,
            } => Self::TaskRunNextCycleCreated {
                parent_cycle_id: parent_cycle_id.to_string(),
                successor_cycle_id: successor_cycle_id.to_string(),
                attempt_id: attempt_id.to_string(),
                sequence: *sequence,
            },
            TaskRunEvent::RetryScheduled {
                ordinal,
                old_attempt_id,
                new_attempt_id,
                abandoned_cycle_id,
                delay_ms,
                due_at_unix_us,
                ..
            } => Self::TaskRunRetryScheduled {
                ordinal: *ordinal,
                old_attempt_id: old_attempt_id.to_string(),
                new_attempt_id: new_attempt_id.to_string(),
                abandoned_cycle_id: abandoned_cycle_id.to_string(),
                delay_millis: *delay_ms,
                due_at_unix_micros: *due_at_unix_us,
            },
            TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal,
                attempt_id,
                activated_at_unix_us,
            } => Self::TaskRunRetryAttemptActivated {
                ordinal: *ordinal,
                attempt_id: attempt_id.to_string(),
                activated_at_unix_micros: *activated_at_unix_us,
            },
            TaskRunEvent::RecoveryResumeStarted {
                new_attempt_id,
                new_generation,
                abandoned_cycle_id,
                ..
            } => Self::TaskRunRecoveryResumeStarted {
                new_attempt_id: new_attempt_id.to_string(),
                new_generation: *new_generation,
                abandoned_cycle_id: abandoned_cycle_id.map(|id| id.to_string()),
            },
            TaskRunEvent::LoopCheckpointStarted { checkpoint_id, .. } => {
                Self::TaskRunLoopCheckpointStarted {
                    checkpoint_id: checkpoint_id.to_string(),
                }
            }
            TaskRunEvent::LoopCheckpointRecorded { checkpoint_id, .. } => {
                Self::TaskRunLoopCheckpointRecorded {
                    checkpoint_id: checkpoint_id.to_string(),
                }
            }
            TaskRunEvent::LoopCheckpointCommitted { checkpoint_id, .. } => {
                Self::TaskRunLoopCheckpointCommitted {
                    checkpoint_id: checkpoint_id.to_string(),
                }
            }
            TaskRunEvent::LoopWakeAccepted {
                cycle_id,
                wake_evidence_ref,
            } => Self::TaskRunLoopWakeAccepted {
                cycle_id: cycle_id.to_string(),
                evidence_id: wake_evidence_ref.evidence_id.to_string(),
                source: wake_evidence_source(wake_evidence_ref.source).to_owned(),
            },
        })
    }
}
