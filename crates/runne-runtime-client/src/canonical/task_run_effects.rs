include!("task_run_effects/models.rs");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskRunEffectsWire {
    task_run_id: CanonicalId,
    stream_version: u64,
    attempt_id: PresentOption<CanonicalId>,
    cancellation_requested: bool,
    local_command: PresentOption<LocalCommandWire>,
    remote: RemoteEffectWire,
    successor: SuccessorWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalCommandWire {
    outcome: LocalOutcomeWire,
    stop: LocalStopWire,
    exit_code: PresentOption<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoteEffectWire {
    outcome: RemoteOutcomeWire,
    publication: RemotePublicationWire,
    accounting: RemoteAccountingWire,
    cancellation: RemoteCancellationWire,
    availability: RemoteAvailabilityWire,
    capabilities: RemoteCapabilitiesWire,
    usage_known: PresentOption<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoteCapabilitiesWire {
    status_check: bool,
    stream_resume: bool,
    remote_cancel: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LocalOutcomeWire {
    NotStarted,
    Running,
    Exited,
    OutcomeUnknown,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LocalStopWire {
    NotRequested,
    Requested,
    Confirmed,
    Unconfirmed,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteOutcomeWire {
    NotApplicable,
    NotStarted,
    Running,
    Completed,
    Failed,
    Incomplete,
    Cancelled,
    Unknown,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemotePublicationWire {
    NotApplicable,
    Unknown,
    Allowed,
    Withheld,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteAccountingWire {
    NotApplicable,
    Unknown,
    Known,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteCancellationWire {
    NotRequested,
    Requested,
    Confirmed,
    Unconfirmed,
    Unknown,
    /// Provider completed and canonical cancellation closure proves no pending rounds.
    AlreadyTerminal,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteAvailabilityWire {
    Available,
    Unavailable,
    NotConfigured,
    Unknown,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SuccessorWire {
    NotApplicable,
    Blocked,
    RequiresDuplicateEffectAcknowledgment,
    Eligible,
}

impl TryFrom<TaskRunEffectsWire> for TaskRunEffectsV1 {
    type Error = RuntimeApiError;

    fn try_from(wire: TaskRunEffectsWire) -> Result<Self, Self::Error> {
        let attempt_id = match wire.attempt_id {
            PresentOption::Present(value) => value,
            PresentOption::Missing => return Err(invalid_task_run_response()),
        };
        let local_command: Option<LocalCommandEffect> = match wire.local_command {
            PresentOption::Present(Some(local)) => Some(local.try_into()?),
            PresentOption::Present(None) => None,
            PresentOption::Missing => return Err(invalid_task_run_response()),
        };
        let remote = RemoteEffect::try_from(wire.remote)?;
        if wire.stream_version == 0
            || local_command.as_ref().is_some_and(|local| {
                (local.outcome == LocalExecutionOutcome::Exited) != local.exit_code.is_some()
                    || (local.outcome != LocalExecutionOutcome::Exited
                        && local.stop == LocalStopEvidence::Confirmed
                        && local.outcome == LocalExecutionOutcome::Running)
            })
            || (remote.cancellation == RemoteCancellationEvidence::Confirmed
                && remote.outcome != RemoteEffectOutcome::Cancelled)
            || (remote.cancellation == RemoteCancellationEvidence::AlreadyTerminal
                && (!wire.cancellation_requested
                    || remote.outcome != RemoteEffectOutcome::Completed))
            || (remote.outcome == RemoteEffectOutcome::NotApplicable
                && (remote.publication != RemotePublicationDisposition::NotApplicable
                    || remote.accounting != RemoteAccountingDisposition::NotApplicable))
            || (remote.publication == RemotePublicationDisposition::Withheld
                && remote.outcome == RemoteEffectOutcome::Unknown)
        {
            return Err(invalid_task_run_response());
        }
        Ok(Self {
            task_run_id: wire.task_run_id,
            stream_version: wire.stream_version,
            attempt_id,
            cancellation_requested: wire.cancellation_requested,
            local_command,
            remote,
            successor: wire.successor.into(),
        })
    }
}

/// Parses a TaskRun effects fixture through the production wire decoder.
/// Available only to test-support consumers so desktop IPC tests exercise the
/// same closed response validation without exposing a production constructor.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_decode_task_run_effects_wire(
    value: serde_json::Value,
) -> Result<TaskRunEffectsV1, RuntimeApiError> {
    let wire = serde_json::from_value::<TaskRunEffectsWire>(value)
        .map_err(|_| invalid_task_run_response())?;
    TaskRunEffectsV1::try_from(wire)
}

impl TryFrom<LocalCommandWire> for LocalCommandEffect {
    type Error = RuntimeApiError;
    fn try_from(wire: LocalCommandWire) -> Result<Self, Self::Error> {
        let PresentOption::Present(exit_code) = wire.exit_code else {
            return Err(invalid_task_run_response());
        };
        Ok(Self {
            outcome: wire.outcome.into(),
            stop: wire.stop.into(),
            exit_code,
        })
    }
}

impl TryFrom<RemoteEffectWire> for RemoteEffect {
    type Error = RuntimeApiError;
    fn try_from(wire: RemoteEffectWire) -> Result<Self, Self::Error> {
        let PresentOption::Present(usage_known) = wire.usage_known else {
            return Err(invalid_task_run_response());
        };
        Ok(Self {
            outcome: wire.outcome.into(),
            publication: wire.publication.into(),
            accounting: wire.accounting.into(),
            cancellation: wire.cancellation.into(),
            availability: wire.availability.into(),
            capabilities: RemoteEffectCapabilities {
                status_check: wire.capabilities.status_check,
                stream_resume: wire.capabilities.stream_resume,
                remote_cancel: wire.capabilities.remote_cancel,
            },
            usage_known,
        })
    }
}

impl From<LocalOutcomeWire> for LocalExecutionOutcome {
    fn from(value: LocalOutcomeWire) -> Self {
        match value {
            LocalOutcomeWire::NotStarted => Self::NotStarted,
            LocalOutcomeWire::Running => Self::Running,
            LocalOutcomeWire::Exited => Self::Exited,
            LocalOutcomeWire::OutcomeUnknown => Self::OutcomeUnknown,
        }
    }
}
impl From<LocalStopWire> for LocalStopEvidence {
    fn from(value: LocalStopWire) -> Self {
        match value {
            LocalStopWire::NotRequested => Self::NotRequested,
            LocalStopWire::Requested => Self::Requested,
            LocalStopWire::Confirmed => Self::Confirmed,
            LocalStopWire::Unconfirmed => Self::Unconfirmed,
        }
    }
}
impl From<RemoteOutcomeWire> for RemoteEffectOutcome {
    fn from(value: RemoteOutcomeWire) -> Self {
        match value {
            RemoteOutcomeWire::NotApplicable => Self::NotApplicable,
            RemoteOutcomeWire::NotStarted => Self::NotStarted,
            RemoteOutcomeWire::Running => Self::Running,
            RemoteOutcomeWire::Completed => Self::Completed,
            RemoteOutcomeWire::Failed => Self::Failed,
            RemoteOutcomeWire::Incomplete => Self::Incomplete,
            RemoteOutcomeWire::Cancelled => Self::Cancelled,
            RemoteOutcomeWire::Unknown => Self::Unknown,
        }
    }
}
impl From<RemotePublicationWire> for RemotePublicationDisposition {
    fn from(value: RemotePublicationWire) -> Self {
        match value {
            RemotePublicationWire::NotApplicable => Self::NotApplicable,
            RemotePublicationWire::Unknown => Self::Unknown,
            RemotePublicationWire::Allowed => Self::Allowed,
            RemotePublicationWire::Withheld => Self::Withheld,
        }
    }
}
impl From<RemoteAccountingWire> for RemoteAccountingDisposition {
    fn from(value: RemoteAccountingWire) -> Self {
        match value {
            RemoteAccountingWire::NotApplicable => Self::NotApplicable,
            RemoteAccountingWire::Unknown => Self::Unknown,
            RemoteAccountingWire::Known => Self::Known,
        }
    }
}
impl From<RemoteCancellationWire> for RemoteCancellationEvidence {
    fn from(value: RemoteCancellationWire) -> Self {
        match value {
            RemoteCancellationWire::NotRequested => Self::NotRequested,
            RemoteCancellationWire::Requested => Self::Requested,
            RemoteCancellationWire::Confirmed => Self::Confirmed,
            RemoteCancellationWire::Unconfirmed => Self::Unconfirmed,
            RemoteCancellationWire::Unknown => Self::Unknown,
            RemoteCancellationWire::AlreadyTerminal => Self::AlreadyTerminal,
        }
    }
}
impl From<RemoteAvailabilityWire> for RemoteEffectAvailability {
    fn from(value: RemoteAvailabilityWire) -> Self {
        match value {
            RemoteAvailabilityWire::Available => Self::Available,
            RemoteAvailabilityWire::Unavailable => Self::Unavailable,
            RemoteAvailabilityWire::NotConfigured => Self::NotConfigured,
            RemoteAvailabilityWire::Unknown => Self::Unknown,
        }
    }
}
impl From<SuccessorWire> for TaskRunSuccessorEligibility {
    fn from(value: SuccessorWire) -> Self {
        match value {
            SuccessorWire::NotApplicable => Self::NotApplicable,
            SuccessorWire::Blocked => Self::Blocked,
            SuccessorWire::RequiresDuplicateEffectAcknowledgment => {
                Self::RequiresDuplicateEffectAcknowledgment
            }
            SuccessorWire::Eligible => Self::Eligible,
        }
    }
}

include!("task_run_effects/client.rs");

#[cfg(test)]
include!("task_run_effects/tests.rs");
