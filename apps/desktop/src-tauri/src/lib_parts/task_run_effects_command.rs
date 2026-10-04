#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunEffectsWire {
    task_run_id: String,
    stream_version: u64,
    attempt_id: Option<String>,
    cancellation_requested: bool,
    local_command: Option<LocalCommandEffectsWire>,
    remote: RemoteEffectsWire,
    successor: &'static str,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalCommandEffectsWire {
    outcome: &'static str,
    stop: &'static str,
    exit_code: Option<i32>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteEffectsWire {
    outcome: &'static str,
    publication: &'static str,
    accounting: &'static str,
    cancellation: &'static str,
    availability: &'static str,
    capabilities: RemoteCapabilitiesWire,
    usage_known: Option<bool>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteCapabilitiesWire {
    status_check: bool,
    stream_resume: bool,
    remote_cancel: bool,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_task_run_effects(
    state: State<'_, Arc<AppCore>>,
    task_run_id: String,
) -> Result<TaskRunEffectsWire, IpcError> {
    let value = state
        .get_task_run_effects(&task_run_id)
        .await
        .map_err(|_| IpcError {
            code: "task_run_effects_unavailable",
        })?;
    Ok(task_run_effects_to_wire(&value))
}

fn task_run_effects_to_wire(value: &runne_app_core::TaskRunEffectsV1) -> TaskRunEffectsWire {
    let local_command = value.local_command().map(|local| LocalCommandEffectsWire {
        outcome: match local.outcome() {
            runne_app_core::LocalExecutionOutcome::NotStarted => "not_started",
            runne_app_core::LocalExecutionOutcome::Running => "running",
            runne_app_core::LocalExecutionOutcome::Exited => "exited",
            runne_app_core::LocalExecutionOutcome::OutcomeUnknown => "outcome_unknown",
        },
        stop: match local.stop() {
            runne_app_core::LocalStopEvidence::NotRequested => "not_requested",
            runne_app_core::LocalStopEvidence::Requested => "requested",
            runne_app_core::LocalStopEvidence::Confirmed => "confirmed",
            runne_app_core::LocalStopEvidence::Unconfirmed => "unconfirmed",
        },
        exit_code: local.exit_code(),
    });
    let remote_effect = value.remote();
    let capabilities = remote_effect.capabilities();
    let remote = RemoteEffectsWire {
        outcome: match remote_effect.outcome() {
            runne_app_core::RemoteEffectOutcome::NotApplicable => "not_applicable",
            runne_app_core::RemoteEffectOutcome::NotStarted => "not_started",
            runne_app_core::RemoteEffectOutcome::Running => "running",
            runne_app_core::RemoteEffectOutcome::Completed => "completed",
            runne_app_core::RemoteEffectOutcome::Failed => "failed",
            runne_app_core::RemoteEffectOutcome::Incomplete => "incomplete",
            runne_app_core::RemoteEffectOutcome::Cancelled => "cancelled",
            runne_app_core::RemoteEffectOutcome::Unknown => "unknown",
        },
        publication: publication_wire(remote_effect.publication()),
        accounting: accounting_wire(remote_effect.accounting()),
        cancellation: match remote_effect.cancellation() {
            runne_app_core::RemoteCancellationEvidence::NotRequested => "not_requested",
            runne_app_core::RemoteCancellationEvidence::Requested => "requested",
            runne_app_core::RemoteCancellationEvidence::Confirmed => "confirmed",
            runne_app_core::RemoteCancellationEvidence::Unconfirmed => "unconfirmed",
            runne_app_core::RemoteCancellationEvidence::Unknown => "unknown",
        },
        availability: match remote_effect.availability() {
            runne_app_core::RemoteEffectAvailability::Available => "available",
            runne_app_core::RemoteEffectAvailability::Unavailable => "unavailable",
            runne_app_core::RemoteEffectAvailability::NotConfigured => "not_configured",
            runne_app_core::RemoteEffectAvailability::Unknown => "unknown",
        },
        capabilities: RemoteCapabilitiesWire {
            status_check: capabilities.status_check(),
            stream_resume: capabilities.stream_resume(),
            remote_cancel: capabilities.remote_cancel(),
        },
        usage_known: remote_effect.usage_known(),
    };
    TaskRunEffectsWire {
        task_run_id: value.task_run_id().to_string(),
        stream_version: value.stream_version(),
        attempt_id: value.attempt_id().map(|id| id.to_string()),
        cancellation_requested: value.cancellation_requested(),
        local_command,
        remote,
        successor: match value.successor() {
            runne_app_core::TaskRunSuccessorEligibility::NotApplicable => "not_applicable",
            runne_app_core::TaskRunSuccessorEligibility::Blocked => "blocked",
            runne_app_core::TaskRunSuccessorEligibility::RequiresDuplicateEffectAcknowledgment => {
                "requires_duplicate_effect_acknowledgment"
            }
            runne_app_core::TaskRunSuccessorEligibility::Eligible => "eligible",
        },
    }
}

const fn publication_wire(value: runne_app_core::RemotePublicationDisposition) -> &'static str {
    match value {
        runne_app_core::RemotePublicationDisposition::NotApplicable => "not_applicable",
        runne_app_core::RemotePublicationDisposition::Unknown => "unknown",
        runne_app_core::RemotePublicationDisposition::Allowed => "allowed",
        runne_app_core::RemotePublicationDisposition::Withheld => "withheld",
    }
}

const fn accounting_wire(value: runne_app_core::RemoteAccountingDisposition) -> &'static str {
    match value {
        runne_app_core::RemoteAccountingDisposition::NotApplicable => "not_applicable",
        runne_app_core::RemoteAccountingDisposition::Unknown => "unknown",
        runne_app_core::RemoteAccountingDisposition::Known => "known",
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "task_run_effects_command_tests.rs"]
mod task_run_effects_wire_tests;
