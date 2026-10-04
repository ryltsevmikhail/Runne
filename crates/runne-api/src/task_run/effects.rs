//! Versioned effect facts kept separate from the stable TaskRun snapshot wire.

use runne_domain::id::{AttemptId, TaskRunId};

/// Consistent TaskRun and external-effect view for one committed stream version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunEffectsV1 {
    pub taskrun_id: TaskRunId,
    pub stream_version: u64,
    pub attempt_id: Option<AttemptId>,
    /// Whether the workflow has durably accepted a cancellation request.
    pub cancellation_requested: bool,
    pub local_command: Option<LocalCommandEffectV1>,
    pub remote: RemoteEffectV1,
    pub successor: SuccessorEligibilityV1,
}

/// Local command execution evidence, independent of workflow terminal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCommandEffectV1 {
    pub outcome: LocalCommandOutcomeV1,
    pub stop: LocalCommandStopV1,
    pub exit_code: Option<i32>,
}

/// Factual local process outcome. Unknown does not imply failure or cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCommandOutcomeV1 {
    NotStarted,
    Running,
    Exited,
    OutcomeUnknown,
}

/// Proof about whether local processes have stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCommandStopV1 {
    NotRequested,
    Requested,
    Confirmed,
    Unconfirmed,
}

/// Remote effect projection with availability and capabilities kept distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEffectV1 {
    pub outcome: RemoteEffectOutcomeV1,
    /// Whether a factual remote artifact's text is safe to expose locally.
    /// This remains independent from the provider's factual outcome.
    pub publication: RemotePublicationV1,
    /// Provider accounting certainty, independent from usage visibility.
    pub accounting: RemoteAccountingV1,
    pub cancellation: RemoteCancellationV1,
    pub availability: RemoteEffectAvailabilityV1,
    pub capabilities: RemoteEffectCapabilitiesV1,
    /// `None` means the adapter has not durably established usage certainty.
    pub usage_known: Option<bool>,
}

/// Local publication decision for remote response text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemotePublicationV1 {
    NotApplicable,
    Unknown,
    Allowed,
    Withheld,
}

/// Financial settlement certainty for a factual remote provider outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteAccountingV1 {
    NotApplicable,
    Unknown,
    Known,
}

/// Factual remote outcome; cancellation intent alone never yields Cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteEffectOutcomeV1 {
    NotApplicable,
    NotStarted,
    Running,
    Completed,
    Failed,
    Incomplete,
    Cancelled,
    Unknown,
}

/// Remote cancellation intent and evidence, separate from remote outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteCancellationV1 {
    NotRequested,
    Requested,
    Confirmed,
    Unconfirmed,
    Unknown,
}

/// Whether the remote adapter can currently be reached for effect reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteEffectAvailabilityV1 {
    Available,
    Unavailable,
    NotConfigured,
    Unknown,
}

/// Closed adapter capabilities advertised independently of current availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteEffectCapabilitiesV1 {
    pub status_check: bool,
    pub stream_resume: bool,
    pub remote_cancel: bool,
}

/// Read-only eligibility result. Returning this value never accepts an acknowledgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessorEligibilityV1 {
    NotApplicable,
    Blocked,
    RequiresDuplicateEffectAcknowledgment,
    Eligible,
}
