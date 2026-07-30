//! Public, transport-neutral replay binding contracts.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use gocode_domain::agent_loop::{LoopDisposition, StepOutcomeType, WakeEvidenceSource};
use gocode_domain::command::TerminalResult;
use gocode_domain::conversation::{ConversationEvent, GenerationFailureReason};
use gocode_domain::event::{EventType, Sensitivity};
use gocode_domain::replay::ReplayScope;
use gocode_domain::task_run::TaskRunEvent;
use serde::Serialize;

use crate::{
    EphemeralRuntimeBinding, LocalSessionContractError, RuntimeSessionBinding, StableRuntimeBinding,
};

/// Maximum UTF-8 bytes in a public TaskRun failure reason.
pub const MAX_CANONICAL_REPLAY_FAILURE_REASON_BYTES: usize = 4096;

/// Aggregate streams exposed through the public replay API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApiReplayAggregateKind {
    /// Conversation aggregate stream.
    Conversation,
    /// Task run aggregate stream.
    TaskRun,
}

impl TryFrom<ReplayScope> for ApiReplayAggregateKind {
    type Error = ReplayContractError;

    fn try_from(scope: ReplayScope) -> Result<Self, Self::Error> {
        match scope {
            ReplayScope::Aggregate {
                aggregate_type: 1, ..
            } => Ok(Self::TaskRun),
            ReplayScope::Aggregate {
                aggregate_type: 2, ..
            } => Ok(Self::Conversation),
            ReplayScope::Aggregate { .. } => Err(ReplayContractError::UnknownAggregateKind),
            ReplayScope::TaskRunFeed { .. } | ReplayScope::AuditFeed { .. } => {
                Err(ReplayContractError::UnsupportedScope)
            }
        }
    }
}

/// Stable failures when adapting an internal replay scope to the public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayContractError {
    /// The domain aggregate selector is not public replay scope.
    UnknownAggregateKind,
    /// The domain scope is an internal feed rather than an aggregate stream.
    UnsupportedScope,
    /// A retention manifest did not contain a usable generation and digest.
    InvalidRetentionManifest,
    /// A gap-range reference was empty.
    InvalidGapRangeRef,
    /// An opaque replay binding identity was empty.
    EmptyBindingId,
    /// A supported canonical event type was empty.
    EmptyEventType,
    /// A supported canonical event type contained a forbidden control byte.
    InvalidEventType,
    /// A supported canonical event schema version was zero.
    InvalidEventSchemaVersion,
}

/// Opaque public replay-binding identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiReplayBindingId([u8; 16]);

impl ApiReplayBindingId {
    /// Creates a non-empty opaque replay-binding identity.
    pub fn new(value: [u8; 16]) -> Result<Self, ReplayContractError> {
        if value == [0; 16] {
            return Err(ReplayContractError::EmptyBindingId);
        }
        Ok(Self(value))
    }

    /// Returns the stable opaque lower-hex wire identity.
    ///
    /// This is a transport identity only; it does not expose storage position
    /// or authority material.
    pub fn to_wire_value(&self) -> String {
        let mut value = String::with_capacity(32);
        for byte in self.0 {
            write!(&mut value, "{byte:02x}").expect("writing to String is infallible");
        }
        value
    }
}

impl core::fmt::Debug for ApiReplayBindingId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ApiReplayBindingId([redacted])")
    }
}

/// A supported canonical event type and its schema version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiReplayEventSchema {
    event_type: String,
    schema_version: u32,
}

impl ApiReplayEventSchema {
    /// Creates a validated public event-type/schema capability.
    pub fn new(
        event_type: impl Into<String>,
        schema_version: u32,
    ) -> Result<Self, ReplayContractError> {
        let event_type = event_type.into();
        if event_type.is_empty() {
            return Err(ReplayContractError::EmptyEventType);
        }
        let event_type = EventType::new(event_type)
            .map_err(|_| ReplayContractError::InvalidEventType)?
            .as_str()
            .to_owned();
        if schema_version == 0 {
            return Err(ReplayContractError::InvalidEventSchemaVersion);
        }
        Ok(Self {
            event_type,
            schema_version,
        })
    }

    /// Returns the canonical event type.
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Returns the supported event schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

/// Retention generation and opaque manifest digest for replay continuity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionManifest {
    generation: u64,
    digest: [u8; 32],
}

impl RetentionManifest {
    /// Creates a non-empty retention manifest reference.
    pub fn new(generation: u64, digest: [u8; 32]) -> Result<Self, ReplayContractError> {
        if generation == 0 || digest == [0; 32] {
            return Err(ReplayContractError::InvalidRetentionManifest);
        }
        Ok(Self { generation, digest })
    }

    /// Returns the retention generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Opaque reference to a compacted replay gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapRangeRef([u8; 32]);

impl GapRangeRef {
    /// Creates a non-empty opaque gap reference.
    pub fn new(reference: [u8; 32]) -> Result<Self, ReplayContractError> {
        if reference == [0; 32] {
            return Err(ReplayContractError::InvalidGapRangeRef);
        }
        Ok(Self(reference))
    }
}

/// Public replay binding version one.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiReplayBindingV1 {
    binding_id: ApiReplayBindingId,
    stable: StableRuntimeBinding,
    ephemeral: EphemeralRuntimeBinding,
    supported_event_schemas: BTreeSet<ApiReplayEventSchema>,
    replay_session_id: [u8; 16],
    retention_manifest: RetentionManifest,
}

impl ApiReplayBindingV1 {
    /// Creates a replay binding tied exactly to one local runtime session.
    pub fn new(
        binding_id: ApiReplayBindingId,
        session: RuntimeSessionBinding,
        authorization_epoch: u64,
        sensitivity_ceiling: Sensitivity,
        supported_event_schemas: impl IntoIterator<Item = ApiReplayEventSchema>,
        replay_session_id: [u8; 16],
        retention_manifest: RetentionManifest,
    ) -> Result<Self, LocalSessionContractError> {
        if authorization_epoch != session.ephemeral().authorization_epoch() {
            return Err(LocalSessionContractError::AuthorizationEpochMismatch);
        }
        if sensitivity_ceiling != session.ephemeral().sensitivity_ceiling() {
            return Err(LocalSessionContractError::SensitivityCeilingMismatch);
        }
        Ok(Self {
            binding_id,
            stable: session.stable().clone(),
            ephemeral: session.ephemeral().clone(),
            supported_event_schemas: supported_event_schemas.into_iter().collect(),
            replay_session_id,
            retention_manifest,
        })
    }

    /// Returns the stable runtime binding.
    pub const fn stable(&self) -> &StableRuntimeBinding {
        &self.stable
    }

    /// Returns the opaque replay-binding identity.
    pub const fn binding_id(&self) -> &ApiReplayBindingId {
        &self.binding_id
    }

    /// Returns the ephemeral runtime binding.
    pub const fn ephemeral(&self) -> &EphemeralRuntimeBinding {
        &self.ephemeral
    }

    /// Returns the supported canonical event-type/schema pairs.
    pub fn supported_event_schemas(&self) -> impl Iterator<Item = &ApiReplayEventSchema> {
        self.supported_event_schemas.iter()
    }

    /// Returns the opaque replay-session identity.
    pub const fn replay_session_id(&self) -> &[u8; 16] {
        &self.replay_session_id
    }

    /// Returns the retention manifest reference.
    pub const fn retention_manifest(&self) -> &RetentionManifest {
        &self.retention_manifest
    }
}

impl core::fmt::Debug for ApiReplayBindingV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApiReplayBindingV1")
            .field("stable", &self.stable)
            .field("ephemeral", &self.ephemeral)
            .field("supported_event_schemas", &self.supported_event_schemas)
            .field("retention_manifest", &self.retention_manifest)
            .finish_non_exhaustive()
    }
}

/// Closed, semantic replay payload published to local runtime clients.
///
/// This DTO intentionally excludes persistence codec bytes, database
/// positions, idempotency material, actor storage bytes, integrity digests,
/// and internal integrity-profile identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
pub enum CanonicalReplayPayloadV1 {
    /// A Conversation was created in one workspace.
    #[serde(rename = "conversation.created")]
    ConversationCreated {
        /// Owning workspace identity.
        workspace_id: String,
    },
    /// A bounded user or assistant message was appended.
    #[serde(rename = "conversation.message.appended")]
    ConversationMessageAppended {
        /// Closed message role.
        role: CanonicalMessageRoleV1,
        /// Message identity.
        message_id: String,
        /// Coordinating task-run identity.
        task_run_id: String,
        /// Exact attempt identity.
        attempt_id: String,
        /// Validated bounded text.
        text: String,
    },
    /// A Conversation generation terminated without an assistant message.
    #[serde(rename = "conversation.generation.failed")]
    ConversationGenerationFailed {
        /// Coordinating task-run identity.
        task_run_id: String,
        /// Exact attempt identity.
        attempt_id: String,
        /// Closed, non-sensitive terminal reason.
        reason: String,
    },
    /// A Conversation was closed.
    #[serde(rename = "conversation.closed")]
    ConversationClosed,
    /// A TaskRun was created.
    #[serde(rename = "taskRun.created")]
    TaskRunCreated,
    /// A TaskRun was queued.
    #[serde(rename = "taskRun.queued")]
    TaskRunQueued,
    /// A TaskRun was admitted.
    #[serde(rename = "taskRun.admitted")]
    TaskRunAdmitted,
    /// A TaskRun attempt started.
    #[serde(rename = "taskRun.attempt.started")]
    TaskRunAttemptStarted {
        /// Attempt identity.
        attempt_id: String,
    },
    /// A TaskRun entered a waiting state.
    #[serde(rename = "taskRun.wait.started")]
    TaskRunWaitStarted,
    /// A TaskRun resumed.
    #[serde(rename = "taskRun.resumed")]
    TaskRunResumed,
    /// A TaskRun retry started.
    #[serde(rename = "taskRun.retry.started")]
    TaskRunRetryStarted {
        /// Retry attempt identity.
        attempt_id: String,
    },
    /// A TaskRun retry completed.
    #[serde(rename = "taskRun.retry.completed")]
    TaskRunRetryCompleted {
        /// Retry attempt identity.
        attempt_id: String,
    },
    /// A TaskRun checkpoint started.
    #[serde(rename = "taskRun.checkpoint.started")]
    TaskRunCheckpointStarted,
    /// A TaskRun checkpoint committed.
    #[serde(rename = "taskRun.checkpoint.committed")]
    TaskRunCheckpointCommitted,
    /// TaskRun cancellation was requested.
    #[serde(rename = "taskRun.cancellation.requested")]
    TaskRunCancellationRequested,
    /// TaskRun cancellation completed.
    #[serde(rename = "taskRun.cancellation.completed")]
    TaskRunCancellationCompleted,
    /// A TaskRun completed with a closed outcome.
    #[serde(rename = "taskRun.completed")]
    TaskRunCompleted {
        /// `success` or `failure`.
        outcome: String,
        /// Redacted failure reason, present only for failure.
        reason: Option<String>,
    },
    /// A TaskRun failed.
    #[serde(rename = "taskRun.failed")]
    TaskRunFailed {
        /// Redacted terminal reason.
        reason: String,
    },
    /// A TaskRun exhausted its budget.
    #[serde(rename = "taskRun.budget.exhausted")]
    TaskRunBudgetExhausted,
    /// Policy denied TaskRun execution.
    #[serde(rename = "taskRun.policy.denied")]
    TaskRunPolicyDenied,
    /// TaskRun reconciliation started.
    #[serde(rename = "taskRun.reconciliation.started")]
    TaskRunReconciliationStarted,
    /// TaskRun reconciliation completed.
    #[serde(rename = "taskRun.reconciliation.completed")]
    TaskRunReconciliationCompleted,
    /// A TaskRun became unrecoverable.
    #[serde(rename = "taskRun.unrecoverable")]
    TaskRunUnrecoverable,
    /// A TaskRun was cancelled directly.
    #[serde(rename = "taskRun.cancelled")]
    TaskRunCancelled,
    /// One TaskRun loop cycle started.
    #[serde(rename = "taskRun.loop.cycle.started")]
    TaskRunLoopCycleStarted {
        /// Cycle identity.
        cycle_id: String,
        /// Attempt identity.
        attempt_id: String,
        /// Aggregate-owned cycle sequence.
        sequence: u64,
        /// Optional parent cycle.
        parent_cycle_id: Option<String>,
    },
    /// One immutable context manifest was committed.
    #[serde(rename = "taskRun.context.committed")]
    TaskRunContextCommitted {
        /// Cycle identity.
        cycle_id: String,
        /// Manifest identity.
        manifest_id: String,
        /// Immutable manifest revision.
        revision: u64,
    },
    /// One immutable plan revision was committed.
    #[serde(rename = "taskRun.plan.committed")]
    TaskRunPlanCommitted {
        /// Cycle identity.
        cycle_id: String,
        /// Plan identity.
        plan_id: String,
        /// Immutable plan revision.
        revision: u64,
        /// Closed ordered proposal indexes.
        expected_proposal_indexes: Vec<u32>,
    },
    /// One proposal outcome was recorded.
    #[serde(rename = "taskRun.step.outcome.recorded")]
    TaskRunStepOutcomeRecorded {
        /// Cycle identity.
        cycle_id: String,
        /// Proposal index.
        proposal_index: u32,
        /// Step identity.
        step_id: String,
        /// Closed outcome spelling.
        outcome: String,
    },
    /// One loop cycle completed.
    #[serde(rename = "taskRun.loop.cycle.completed")]
    TaskRunLoopCycleCompleted {
        /// Cycle identity.
        cycle_id: String,
        /// Attempt identity.
        attempt_id: String,
        /// Closed disposition spelling.
        disposition: String,
    },
    /// One successor cycle was reserved.
    #[serde(rename = "taskRun.next.cycle.created")]
    TaskRunNextCycleCreated {
        /// Parent cycle identity.
        parent_cycle_id: String,
        /// Successor cycle identity.
        successor_cycle_id: String,
        /// Attempt identity.
        attempt_id: String,
        /// Aggregate-owned cycle sequence.
        sequence: u64,
    },
    /// One retry was durably scheduled.
    #[serde(rename = "taskRun.retry.scheduled")]
    TaskRunRetryScheduled {
        /// Retry ordinal.
        ordinal: u64,
        /// Superseded attempt identity.
        old_attempt_id: String,
        /// Reserved retry attempt identity.
        new_attempt_id: String,
        /// Abandoned cycle identity.
        abandoned_cycle_id: String,
        /// Bounded retry delay.
        delay_millis: u64,
        /// Scheduled activation time.
        due_at_unix_micros: i64,
    },
    /// A scheduled retry attempt was activated.
    #[serde(rename = "taskRun.retry.attempt.activated")]
    TaskRunRetryAttemptActivated {
        /// Retry ordinal.
        ordinal: u64,
        /// Activated attempt identity.
        attempt_id: String,
        /// Activation time.
        activated_at_unix_micros: i64,
    },
    /// Recovery reconciliation resumed execution.
    #[serde(rename = "taskRun.recovery.resume.started")]
    TaskRunRecoveryResumeStarted {
        /// New attempt identity.
        new_attempt_id: String,
        /// Monotonic recovery generation.
        new_generation: u64,
        /// Optional abandoned cycle.
        abandoned_cycle_id: Option<String>,
    },
    /// A loop checkpoint batch started.
    #[serde(rename = "taskRun.loop.checkpoint.started")]
    TaskRunLoopCheckpointStarted {
        /// Checkpoint identity.
        checkpoint_id: String,
    },
    /// A loop checkpoint body was recorded.
    #[serde(rename = "taskRun.loop.checkpoint.recorded")]
    TaskRunLoopCheckpointRecorded {
        /// Checkpoint identity.
        checkpoint_id: String,
    },
    /// A loop checkpoint batch committed.
    #[serde(rename = "taskRun.loop.checkpoint.committed")]
    TaskRunLoopCheckpointCommitted {
        /// Checkpoint identity.
        checkpoint_id: String,
    },
    /// Exact wake evidence was accepted.
    #[serde(rename = "taskRun.loop.wake.accepted")]
    TaskRunLoopWakeAccepted {
        /// Cycle identity.
        cycle_id: String,
        /// Wake-evidence identity.
        evidence_id: String,
        /// Closed authority source.
        source: String,
    },
}

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

fn bounded_failure_reason(reason: &str) -> Result<String, CanonicalReplayPayloadError> {
    if reason.is_empty() || reason.len() > MAX_CANONICAL_REPLAY_FAILURE_REASON_BYTES {
        return Err(CanonicalReplayPayloadError::InvalidFailureReason);
    }
    Ok(reason.to_owned())
}

const fn generation_failure_reason(reason: GenerationFailureReason) -> &'static str {
    match reason {
        GenerationFailureReason::ProviderOutputRejected => "provider_output_rejected",
    }
}

const fn step_outcome_type(outcome: StepOutcomeType) -> &'static str {
    match outcome {
        StepOutcomeType::Succeeded => "succeeded",
        StepOutcomeType::FailedBeforeCommit => "failed_before_commit",
        StepOutcomeType::FailedAfterCommit => "failed_after_commit",
        StepOutcomeType::Uncertain => "uncertain",
        StepOutcomeType::Cancelled => "cancelled",
    }
}

const fn loop_disposition(disposition: &LoopDisposition) -> &'static str {
    match disposition {
        LoopDisposition::Continue => "continue",
        LoopDisposition::Wait { .. } => "wait",
        LoopDisposition::Complete { .. } => "complete",
        LoopDisposition::Fail { .. } => "fail",
    }
}

const fn wake_evidence_source(source: WakeEvidenceSource) -> &'static str {
    match source {
        WakeEvidenceSource::ExternalInput => "external_input",
        WakeEvidenceSource::Approval => "approval",
        WakeEvidenceSource::ChildTaskRun => "child_task_run",
        WakeEvidenceSource::Timer => "timer",
        WakeEvidenceSource::Reconciliation => "reconciliation",
    }
}
