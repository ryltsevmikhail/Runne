#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunEffectsWire {
    task_run_id: String,
    stream_version: u64,
    attempt_id: Option<String>,
    cancellation_requested: bool,
    local_command: Option<TaskRunLocalEffectsWire>,
    remote: RemoteEffectWire,
    successor: &'static str,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunLocalEffectsWire {
    outcome: &'static str,
    stop: &'static str,
    exit_code: Option<i32>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteEffectWire {
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

async fn get_task_run_effects<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
) -> Response
where
    H: TaskRunQueryHostPort,
{
    let taskrun_id = match taskrun_id.parse::<TaskRunId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_id", &request_id),
    };
    match state.host.get_task_run_effects(taskrun_id).await {
        Ok(effects) => (StatusCode::OK, Json(effects_to_wire(effects))).into_response(),
        Err(error) => effect_error(error, &request_id),
    }
}

fn effect_error(error: TaskRunHostError, request_id: &RequestId) -> Response {
    let status = match error {
        TaskRunHostError::NotFound => StatusCode::NOT_FOUND,
        TaskRunHostError::Conflict => StatusCode::CONFLICT,
        TaskRunHostError::Backpressure | TaskRunHostError::Unavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        TaskRunHostError::InvariantViolation => StatusCode::INTERNAL_SERVER_ERROR,
    };
    canonical_error_response(status, error.code(), request_id)
}

fn effects_to_wire(value: TaskRunEffectsV1) -> TaskRunEffectsWire {
    let local_command = value.local_command.map(|local| TaskRunLocalEffectsWire {
        outcome: match local.outcome {
            runne_api::LocalCommandOutcomeV1::NotStarted => "not_started",
            runne_api::LocalCommandOutcomeV1::Running => "running",
            runne_api::LocalCommandOutcomeV1::Exited => "exited",
            runne_api::LocalCommandOutcomeV1::OutcomeUnknown => "outcome_unknown",
        },
        stop: match local.stop {
            runne_api::LocalCommandStopV1::NotRequested => "not_requested",
            runne_api::LocalCommandStopV1::Requested => "requested",
            runne_api::LocalCommandStopV1::Confirmed => "confirmed",
            runne_api::LocalCommandStopV1::Unconfirmed => "unconfirmed",
        },
        exit_code: local.exit_code,
    });
    let remote = RemoteEffectWire {
        outcome: match value.remote.outcome {
            runne_api::RemoteEffectOutcomeV1::NotApplicable => "not_applicable",
            runne_api::RemoteEffectOutcomeV1::NotStarted => "not_started",
            runne_api::RemoteEffectOutcomeV1::Running => "running",
            runne_api::RemoteEffectOutcomeV1::Completed => "completed",
            runne_api::RemoteEffectOutcomeV1::Failed => "failed",
            runne_api::RemoteEffectOutcomeV1::Incomplete => "incomplete",
            runne_api::RemoteEffectOutcomeV1::Cancelled => "cancelled",
            runne_api::RemoteEffectOutcomeV1::Unknown => "unknown",
        },
        publication: match value.remote.publication {
            runne_api::RemotePublicationV1::NotApplicable => "not_applicable",
            runne_api::RemotePublicationV1::Unknown => "unknown",
            runne_api::RemotePublicationV1::Allowed => "allowed",
            runne_api::RemotePublicationV1::Withheld => "withheld",
        },
        accounting: match value.remote.accounting {
            runne_api::RemoteAccountingV1::NotApplicable => "not_applicable",
            runne_api::RemoteAccountingV1::Unknown => "unknown",
            runne_api::RemoteAccountingV1::Known => "known",
        },
        cancellation: match value.remote.cancellation {
            runne_api::RemoteCancellationV1::NotRequested => "not_requested",
            runne_api::RemoteCancellationV1::Requested => "requested",
            runne_api::RemoteCancellationV1::Confirmed => "confirmed",
            runne_api::RemoteCancellationV1::Unconfirmed => "unconfirmed",
            runne_api::RemoteCancellationV1::Unknown => "unknown",
            runne_api::RemoteCancellationV1::AlreadyTerminal => "already_terminal",
        },
        availability: match value.remote.availability {
            runne_api::RemoteEffectAvailabilityV1::Available => "available",
            runne_api::RemoteEffectAvailabilityV1::Unavailable => "unavailable",
            runne_api::RemoteEffectAvailabilityV1::NotConfigured => "not_configured",
            runne_api::RemoteEffectAvailabilityV1::Unknown => "unknown",
        },
        capabilities: RemoteCapabilitiesWire {
            status_check: value.remote.capabilities.status_check,
            stream_resume: value.remote.capabilities.stream_resume,
            remote_cancel: value.remote.capabilities.remote_cancel,
        },
        usage_known: value.remote.usage_known,
    };
    TaskRunEffectsWire {
        task_run_id: value.taskrun_id.to_string(),
        stream_version: value.stream_version,
        attempt_id: value.attempt_id.map(|id| id.to_string()),
        cancellation_requested: value.cancellation_requested,
        local_command,
        remote,
        successor: match value.successor {
            runne_api::SuccessorEligibilityV1::NotApplicable => "not_applicable",
            runne_api::SuccessorEligibilityV1::Blocked => "blocked",
            runne_api::SuccessorEligibilityV1::RequiresDuplicateEffectAcknowledgment => {
                "requires_duplicate_effect_acknowledgment"
            }
            runne_api::SuccessorEligibilityV1::Eligible => "eligible",
        },
    }
}

#[cfg(test)]
mod cancellation_wire_tests {
    use super::effects_to_wire;
    use runne_api::{
        RemoteAccountingV1, RemoteCancellationV1, RemoteEffectAvailabilityV1,
        RemoteEffectCapabilitiesV1, RemoteEffectOutcomeV1, RemoteEffectV1, RemotePublicationV1,
        SuccessorEligibilityV1, TaskRunEffectsV1,
    };

    #[test]
    fn already_terminal_wire_preserves_completed_outcome() {
        let effects = TaskRunEffectsV1 {
            taskrun_id: "018f1234-5678-7000-8000-000000000001".parse().unwrap(),
            stream_version: 9,
            attempt_id: None,
            cancellation_requested: true,
            local_command: None,
            remote: RemoteEffectV1 {
                outcome: RemoteEffectOutcomeV1::Completed,
                publication: RemotePublicationV1::Withheld,
                accounting: RemoteAccountingV1::Known,
                cancellation: RemoteCancellationV1::AlreadyTerminal,
                availability: RemoteEffectAvailabilityV1::Available,
                capabilities: RemoteEffectCapabilitiesV1 {
                    status_check: false,
                    stream_resume: false,
                    remote_cancel: false,
                },
                usage_known: Some(true),
            },
            successor: SuccessorEligibilityV1::NotApplicable,
        };
        let wire = serde_json::to_value(effects_to_wire(effects)).unwrap();
        assert_eq!(wire["remote"]["cancellation"], "already_terminal");
        assert_eq!(wire["remote"]["outcome"], "completed");
        assert_eq!(wire["remote"]["publication"], "withheld");
        assert_eq!(wire["cancellationRequested"], true);
    }
}
