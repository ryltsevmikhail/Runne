use runne_provider::{
    AttemptId, DispatchAttemptId, ProviderRecoveryBinding, RemoteResponseId, TaskRunId,
};
use runne_provider_openai::{
    OpenAiResponsesTextProfile, OpenAiStreamError, OpenAiValidatedBackgroundTerminal,
};
use serde_json::{Value, json};

const PROFILE: &[u8] =
    include_bytes!("../../../docs/profiles/openai-responses-background-text-v1.json");

fn parse(value: &Value) -> Result<OpenAiValidatedBackgroundTerminal, OpenAiStreamError> {
    let profile = OpenAiResponsesTextProfile::from_json(PROFILE).unwrap();
    OpenAiValidatedBackgroundTerminal::from_json(
        &serde_json::to_vec(value).unwrap(),
        &profile,
        &RemoteResponseId::new("resp_exact_1").unwrap(),
    )
}

fn usage() -> Value {
    json!({"input_tokens":1,"output_tokens":1,"total_tokens":2,
        "input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}})
}

fn binding() -> ProviderRecoveryBinding {
    ProviderRecoveryBinding::new(
        TaskRunId::from_bytes([1; 16]),
        AttemptId::from_bytes([2; 16]),
        DispatchAttemptId::from_bytes([3; 16]),
        [4; 32],
    )
    .unwrap()
}

fn response(status: &str) -> Value {
    json!({"id":"resp_exact_1","object":"response","model":"gpt-5.5-2026-04-23",
        "service_tier":"default","background":true,"store":false,"status":status,
        "output":[],"usage":usage()})
}

fn terminal_with_partial_output(response_status: &str, message_status: &str) -> Value {
    let mut value = response(response_status);
    value["output"] = json!([{"id":"msg_1","type":"message","role":"assistant",
        "status":message_status,"content":[{"type":"output_text","annotations":[],"text":"partial text"}]}]);
    match response_status {
        "failed" => value["error"] = json!({"code":"server_error","message":"safe"}),
        "incomplete" => value["incomplete_details"] = json!({"reason":"max_output_tokens"}),
        _ => {}
    }
    value
}

#[test]
fn pending_and_unknown_states_are_not_terminal_evidence() {
    for status in ["queued", "in_progress", "future_state"] {
        assert_eq!(
            parse(&response(status)).unwrap_err(),
            OpenAiStreamError::TerminalMissing
        );
    }
}

#[test]
fn failed_and_incomplete_terminal_fields_are_required_and_well_typed() {
    let mut failed = response("failed");
    assert!(parse(&failed).is_err());
    failed["error"] = json!({"code":"server_error","message":"safe"});
    assert!(parse(&failed).is_ok());

    let mut incomplete = response("incomplete");
    assert!(parse(&incomplete).is_err());
    incomplete["incomplete_details"] = json!({"reason":"max_output_tokens"});
    assert!(parse(&incomplete).is_ok());

    failed["error"]["code"] = json!(5);
    assert!(parse(&failed).is_err());
}

#[test]
fn profile_binding_and_completed_terminal_require_exact_identity_and_output() {
    let mut completed = response("completed");
    completed["output"] = json!([{"id":"msg_1","type":"message","role":"assistant",
        "status":"completed","content":[{"type":"output_text","annotations":[],"text":"ok"}]}]);
    assert!(parse(&completed).is_ok());
    completed["id"] = json!("resp_other");
    assert!(parse(&completed).is_err());
    completed["id"] = json!("resp_exact_1");
    completed["background"] = json!(false);
    assert!(parse(&completed).is_err());
}

#[test]
fn terminal_response_and_output_message_statuses_are_validated_separately() {
    for (response_status, message_status) in [
        ("failed", "incomplete"),
        ("incomplete", "incomplete"),
        ("cancelled", "in_progress"),
    ] {
        let parsed = parse(&terminal_with_partial_output(
            response_status,
            message_status,
        ))
        .unwrap();
        assert_eq!(parsed.output_text(), Some("partial text"));
    }

    for (response_status, message_status) in [
        ("failed", "failed"),
        ("cancelled", "cancelled"),
        ("completed", "incomplete"),
    ] {
        assert!(
            parse(&terminal_with_partial_output(
                response_status,
                message_status
            ))
            .is_err()
        );
    }
}

#[test]
fn terminal_artifact_preserves_text_actual_outcome_and_usage() {
    let mut completed = response("completed");
    completed["output"] = json!([{"id":"msg_1","type":"message","role":"assistant",
        "status":"completed","content":[{"type":"output_text","annotations":[],"text":"answer"}]}]);
    let check = parse(&completed)
        .unwrap()
        .into_remote_check(binding())
        .unwrap();
    assert_eq!(check.terminal().unwrap().output_text(), Some("answer"));
    assert!(matches!(
        check.status(),
        runne_provider::ProviderRemoteResponseStatus::Completed { usage: Some(value) }
            if value.input_tokens() == 1 && value.output_tokens() == 1
    ));

    let cancelled = terminal_with_partial_output("cancelled", "in_progress");
    let check = parse(&cancelled)
        .unwrap()
        .into_remote_check(binding())
        .unwrap();
    assert_eq!(
        check.terminal().unwrap().output_text(),
        Some("partial text")
    );
    assert!(matches!(
        check.status(),
        runne_provider::ProviderRemoteResponseStatus::Cancelled { usage: Some(_) }
    ));
}

#[test]
fn completed_without_usage_preserves_remote_fact_and_marks_finance_unavailable() {
    let mut completed = response("completed");
    completed["output"] = json!([{"id":"msg_1","type":"message","role":"assistant",
        "status":"completed","content":[{"type":"output_text","annotations":[],"text":"answer"}]}]);

    for absent_usage in [None, Some(Value::Null)] {
        if let Some(value) = absent_usage {
            completed["usage"] = value;
        } else {
            completed.as_object_mut().unwrap().remove("usage");
        }
        let parsed = parse(&completed).unwrap();
        assert!(matches!(
            parsed.status(),
            runne_provider::ProviderRemoteResponseStatus::Completed { usage: None }
        ));
        let check = parsed.into_remote_check(binding()).unwrap();
        assert_eq!(check.terminal().unwrap().output_text(), Some("answer"));
        assert!(matches!(
            check.status(),
            runne_provider::ProviderRemoteResponseStatus::Completed { usage: None }
        ));
    }

    completed["usage"] = json!({"input_tokens": "bad"});
    assert_eq!(
        parse(&completed).unwrap_err(),
        OpenAiStreamError::InvalidUsage
    );
}

#[test]
fn large_terminal_is_factually_retained_but_rejected_for_local_publication() {
    let mut completed = response("completed");
    completed["output"] = json!([{"id":"msg_1","type":"message","role":"assistant",
        "status":"completed","content":[{"type":"output_text","annotations":[],"text":"x".repeat(65_537)}]}]);
    let check = parse(&completed)
        .unwrap()
        .into_remote_check(binding())
        .unwrap();
    let terminal = check.terminal().unwrap();
    assert_eq!(terminal.output_text(), None);
    assert_eq!(
        terminal.publication_disposition(),
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::OutputLimitExceeded
        )
    );
    assert!(matches!(
        check.status(),
        runne_provider::ProviderRemoteResponseStatus::Completed { usage: Some(value) }
            if value.input_tokens() == 1 && value.output_tokens() == 1
    ));
}
