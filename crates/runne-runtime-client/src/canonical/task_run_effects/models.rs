/// Local execution outcome, independent from `TaskRun` workflow state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalExecutionOutcome {
    NotStarted,
    Running,
    Exited,
    OutcomeUnknown,
}

/// Evidence that a local command's managed process area has stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalStopEvidence {
    NotRequested,
    Requested,
    Confirmed,
    Unconfirmed,
}

/// Remote effect outcome established by a durable provider fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteEffectOutcome {
    NotApplicable,
    NotStarted,
    Running,
    Completed,
    Failed,
    Incomplete,
    Cancelled,
    Unknown,
}

/// Whether authenticated remote response text may be published locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemotePublicationDisposition {
    NotApplicable,
    Unknown,
    Allowed,
    Withheld,
}

/// Whether provider accounting has an exact durable settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAccountingDisposition {
    NotApplicable,
    Unknown,
    Known,
}

/// Remote cancellation request and evidence, distinct from remote outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteCancellationEvidence {
    NotRequested,
    Requested,
    Confirmed,
    Unconfirmed,
    Unknown,
}

/// Current reconciliation availability, separate from adapter capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteEffectAvailability {
    Available,
    Unavailable,
    NotConfigured,
    Unknown,
}

/// Closed read-only eligibility result; GET does not accept an acknowledgment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskRunSuccessorEligibility {
    NotApplicable,
    Blocked,
    RequiresDuplicateEffectAcknowledgment,
    Eligible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteEffectCapabilities {
    status_check: bool,
    stream_resume: bool,
    remote_cancel: bool,
}

impl RemoteEffectCapabilities {
    #[must_use]
    pub const fn status_check(self) -> bool {
        self.status_check
    }
    #[must_use]
    pub const fn stream_resume(self) -> bool {
        self.stream_resume
    }
    #[must_use]
    pub const fn remote_cancel(self) -> bool {
        self.remote_cancel
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCommandEffect {
    outcome: LocalExecutionOutcome,
    stop: LocalStopEvidence,
    exit_code: Option<i32>,
}

impl LocalCommandEffect {
    #[must_use]
    pub const fn outcome(&self) -> LocalExecutionOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn stop(&self) -> LocalStopEvidence {
        self.stop
    }
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteEffect {
    outcome: RemoteEffectOutcome,
    publication: RemotePublicationDisposition,
    accounting: RemoteAccountingDisposition,
    cancellation: RemoteCancellationEvidence,
    availability: RemoteEffectAvailability,
    capabilities: RemoteEffectCapabilities,
    usage_known: Option<bool>,
}

impl RemoteEffect {
    #[must_use]
    pub const fn outcome(&self) -> RemoteEffectOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn publication(&self) -> RemotePublicationDisposition {
        self.publication
    }
    #[must_use]
    pub const fn accounting(&self) -> RemoteAccountingDisposition {
        self.accounting
    }
    #[must_use]
    pub const fn cancellation(&self) -> RemoteCancellationEvidence {
        self.cancellation
    }
    #[must_use]
    pub const fn availability(&self) -> RemoteEffectAvailability {
        self.availability
    }
    #[must_use]
    pub const fn capabilities(&self) -> RemoteEffectCapabilities {
        self.capabilities
    }
    #[must_use]
    pub const fn usage_known(&self) -> Option<bool> {
        self.usage_known
    }
}

/// Versioned projection retrieved independently of the legacy `TaskRun` snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRunEffectsV1 {
    task_run_id: CanonicalId,
    stream_version: u64,
    attempt_id: Option<CanonicalId>,
    cancellation_requested: bool,
    local_command: Option<LocalCommandEffect>,
    remote: RemoteEffect,
    successor: TaskRunSuccessorEligibility,
}

impl TaskRunEffectsV1 {
    #[must_use]
    pub const fn task_run_id(&self) -> CanonicalId {
        self.task_run_id
    }
    #[must_use]
    pub const fn stream_version(&self) -> u64 {
        self.stream_version
    }
    #[must_use]
    pub const fn attempt_id(&self) -> Option<CanonicalId> {
        self.attempt_id
    }
    #[must_use]
    pub const fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }
    #[must_use]
    pub const fn local_command(&self) -> Option<&LocalCommandEffect> {
        self.local_command.as_ref()
    }
    #[must_use]
    pub const fn remote(&self) -> &RemoteEffect {
        &self.remote
    }
    #[must_use]
    pub const fn successor(&self) -> TaskRunSuccessorEligibility {
        self.successor
    }
}
