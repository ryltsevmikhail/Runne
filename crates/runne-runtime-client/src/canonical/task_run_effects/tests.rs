#[cfg(test)]
mod effects_wire_tests {
    use super::*;

    fn wire(id: CanonicalId) -> serde_json::Value {
        serde_json::json!({
            "taskRunId": id.to_string(),
            "streamVersion": 8,
            "attemptId": null,
            "cancellationRequested": true,
            "localCommand": null,
            "remote": {
                "outcome": "unknown",
                "publication": "unknown",
                "accounting": "unknown",
                "cancellation": "requested",
                "availability": "unavailable",
                "capabilities": {
                    "statusCheck": true,
                    "streamResume": false,
                    "remoteCancel": true
                },
                "usageKnown": null
            },
            "successor": "requires_duplicate_effect_acknowledgment"
        })
    }

    #[test]
    fn remote_cancel_request_stays_separate_from_unknown_outcome() {
        let id = CanonicalId::now_v7();
        let decoded = decode_effects(wire(id)).expect("closed effects projection");
        assert_eq!(decoded.task_run_id(), id);
        assert!(decoded.cancellation_requested());
        assert_eq!(decoded.remote().outcome(), RemoteEffectOutcome::Unknown);
        assert_eq!(
            decoded.remote().publication(),
            RemotePublicationDisposition::Unknown
        );
        assert_eq!(
            decoded.remote().accounting(),
            RemoteAccountingDisposition::Unknown
        );
        assert_eq!(
            decoded.remote().cancellation(),
            RemoteCancellationEvidence::Requested
        );
        assert_eq!(
            decoded.remote().availability(),
            RemoteEffectAvailability::Unavailable
        );
        assert!(decoded.remote().capabilities().status_check());
        assert!(!decoded.remote().capabilities().stream_resume());
        assert!(decoded.remote().capabilities().remote_cancel());
        assert_eq!(
            decoded.successor(),
            TaskRunSuccessorEligibility::RequiresDuplicateEffectAcknowledgment
        );
    }

    #[test]
    fn malformed_or_unknown_effect_fields_are_rejected() {
        let id = CanonicalId::now_v7();
        let mut value = wire(id);
        value["privateResponseText"] = serde_json::json!("must not be exposed");
        assert!(decode_effects(value).is_err());

        let mut value = wire(id);
        value["remote"]["outcome"] = serde_json::json!("cancelled");
        value["remote"]["publication"] = serde_json::json!("withheld");
        value["remote"]["cancellation"] = serde_json::json!("requested");
        assert!(
            decode_effects(value.clone()).is_ok(),
            "request is not cancellation proof"
        );
        value["remote"]["cancellation"] = serde_json::json!("confirmed");
        assert!(
            decode_effects(value.clone()).is_ok(),
            "confirmed remote cancellation requires and accepts factual cancelled outcome"
        );
        value["remote"]["outcome"] = serde_json::json!("completed");
        assert!(
            decode_effects(value).is_err(),
            "confirmed cancel requires factual cancelled outcome"
        );
    }

    #[test]
    fn completed_remote_effect_remains_completed_after_cancel_request() {
        let id = CanonicalId::now_v7();
        let mut value = wire(id);
        value["remote"]["outcome"] = serde_json::json!("completed");
        value["remote"]["cancellation"] = serde_json::json!("requested");
        let decoded = decode_effects(value).expect("completed fact remains valid");
        assert_eq!(decoded.remote().outcome(), RemoteEffectOutcome::Completed);
        assert_eq!(
            decoded.remote().publication(),
            RemotePublicationDisposition::Unknown
        );
        assert_eq!(
            decoded.remote().cancellation(),
            RemoteCancellationEvidence::Requested
        );
    }

    #[test]
    fn withheld_publication_and_unknown_accounting_do_not_rewrite_remote_status() {
        let id = CanonicalId::now_v7();
        let mut value = wire(id);
        value["remote"]["outcome"] = serde_json::json!("completed");
        value["remote"]["publication"] = serde_json::json!("withheld");
        value["remote"]["accounting"] = serde_json::json!("unknown");
        value["remote"]["usageKnown"] = serde_json::json!(true);
        let decoded = decode_effects(value).expect("closed factual projection");
        assert_eq!(decoded.remote().outcome(), RemoteEffectOutcome::Completed);
        assert_eq!(
            decoded.remote().publication(),
            RemotePublicationDisposition::Withheld
        );
        assert_eq!(
            decoded.remote().accounting(),
            RemoteAccountingDisposition::Unknown
        );
        assert_eq!(decoded.remote().usage_known(), Some(true));
    }

    #[test]
    fn local_exit_code_is_reported_as_fact_not_taskrun_state() {
        let id = CanonicalId::now_v7();
        let attempt = CanonicalId::now_v7();
        let mut value = wire(id);
        value["attemptId"] = serde_json::json!(attempt.to_string());
        value["cancellationRequested"] = serde_json::json!(false);
        value["localCommand"] = serde_json::json!({
            "outcome": "exited",
            "stop": "confirmed",
            "exitCode": 7
        });
        value["remote"] = serde_json::json!({
            "outcome": "not_applicable",
            "publication": "not_applicable",
            "accounting": "not_applicable",
            "cancellation": "not_requested",
            "availability": "not_configured",
            "capabilities": {"statusCheck": false, "streamResume": false, "remoteCancel": false},
            "usageKnown": null
        });
        let decoded = decode_effects(value).expect("valid local exit facts");
        let local = decoded.local_command().expect("local effect");
        assert_eq!(local.outcome(), LocalExecutionOutcome::Exited);
        assert_eq!(local.stop(), LocalStopEvidence::Confirmed);
        assert_eq!(local.exit_code(), Some(7));
        assert_eq!(decoded.attempt_id(), Some(attempt));
    }

    fn decode_effects(value: serde_json::Value) -> Result<TaskRunEffectsV1, RuntimeApiError> {
        let wire: TaskRunEffectsWire =
            serde_json::from_value(value).map_err(|_| invalid_task_run_response())?;
        TaskRunEffectsV1::try_from(wire)
    }
}
