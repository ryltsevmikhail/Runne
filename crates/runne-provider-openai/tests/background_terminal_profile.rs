#[path = "support/mod.rs"]
mod support;

use runne_provider::{
    AttemptId, DispatchAttemptId, ProviderRecoveryBinding, RemoteResponseId, TaskRunId,
};
use runne_provider_openai::{
    OpenAiBackgroundResponse, OpenAiResponsesTextProfile, OpenAiValidatedBackgroundTerminal,
};
use serde_json::{Value, json};

const BACKGROUND_PROFILE: &[u8] =
    include_bytes!("../../../docs/profiles/openai-responses-background-text-v1.json");

fn usage() -> Value {
    json!({"input_tokens":8,"output_tokens":3,"total_tokens":11,
        "input_tokens_details":{"cached_tokens":2},"output_tokens_details":{"reasoning_tokens":1}})
}

fn terminal_value(status: &str, usage: Option<Value>) -> Value {
    let mut response = json!({
        "id":"resp_exact_1", "object":"response", "model":"gpt-5.5-2026-04-23",
        "service_tier":"default", "background":true, "store":false, "status":status,
        "output":[], "error":null, "incomplete_details":null,
    });
    if let Some(usage) = usage {
        response["usage"] = usage;
    }
    match status {
        "completed" => {
            response["output"] = json!([{
                "id":"msg_exact_1", "type":"message", "role":"assistant", "status":"completed",
                "content":[{"type":"output_text","annotations":[],"text":"finished text"}]
            }]);
        }
        "failed" => response["error"] = json!({"code":"server_error","message":"safe test error"}),
        "incomplete" => response["incomplete_details"] = json!({"reason":"max_output_tokens"}),
        _ => {}
    }
    response
}

fn terminal(status: &str, usage: Option<Value>) -> OpenAiValidatedBackgroundTerminal {
    let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
    OpenAiValidatedBackgroundTerminal::from_json(
        &serde_json::to_vec(&terminal_value(status, usage)).unwrap(),
        &profile,
        &RemoteResponseId::new("resp_exact_1").unwrap(),
    )
    .unwrap()
}

#[test]
fn terminal_json_is_profile_bound_and_preserves_outcome_and_usage() {
    let completed = terminal("completed", Some(usage()));
    assert_eq!(completed.output_text(), Some("finished text"));
    assert!(
        matches!(completed.status(), runne_provider::ProviderRemoteResponseStatus::Completed { usage: Some(value) } if value.input_tokens() == 8)
    );
    for status in ["failed", "incomplete", "cancelled"] {
        let item = terminal(status, Some(usage()));
        assert_eq!(item.output_text(), None);
        match (status, item.status()) {
            (
                "failed",
                runne_provider::ProviderRemoteResponseStatus::Failed {
                    usage: Some(actual),
                    ..
                },
            ) => assert_eq!(actual.input_tokens(), 8),
            (
                "incomplete",
                runne_provider::ProviderRemoteResponseStatus::Incomplete {
                    usage: Some(actual),
                    ..
                },
            ) => assert_eq!(actual.output_tokens(), 3),
            (
                "cancelled",
                runne_provider::ProviderRemoteResponseStatus::Cancelled {
                    usage: Some(actual),
                },
            ) => assert_eq!(actual.cached_input_tokens(), 2),
            _ => panic!("unexpected validated outcome for {status}"),
        }
    }
}

#[test]
fn terminal_json_requires_exact_profile_identity_status_and_safe_output() {
    let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
    let response_id = RemoteResponseId::new("resp_exact_1").unwrap();
    let valid = terminal_value("completed", Some(usage()));
    let parse = |value: &Value| {
        OpenAiValidatedBackgroundTerminal::from_json(
            &serde_json::to_vec(value).unwrap(),
            &profile,
            &response_id,
        )
    };
    let mut wrong_id = valid.clone();
    wrong_id["id"] = json!("resp_other");
    assert!(parse(&wrong_id).is_err());
    let mut wrong_model = valid.clone();
    wrong_model["model"] = json!("other-model");
    assert!(parse(&wrong_model).is_err());
    let mut wrong_tier = valid.clone();
    wrong_tier["service_tier"] = json!("flex");
    assert!(parse(&wrong_tier).is_err());
    let mut tool = valid.clone();
    tool["output"] = json!([{"id":"fc_1","type":"function_call"}]);
    assert!(parse(&tool).is_err());
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("status");
    assert!(parse(&missing).is_err());
    let mut malformed_usage = valid;
    malformed_usage["usage"]["total_tokens"] = json!(999);
    assert!(parse(&malformed_usage).is_err());
    let mut oversized = terminal_value("completed", Some(usage()));
    oversized["output"][0]["content"][0]["text"] = json!("x".repeat(65_537));
    let binding = ProviderRecoveryBinding::new(
        TaskRunId::from_bytes([1; 16]),
        AttemptId::from_bytes([2; 16]),
        DispatchAttemptId::from_bytes([3; 16]),
        [4; 32],
    )
    .unwrap();
    let check = parse(&oversized)
        .unwrap()
        .into_remote_check(binding)
        .unwrap();
    assert_eq!(check.terminal().unwrap().output_text(), None);
    assert_eq!(
        check.terminal().unwrap().publication_disposition(),
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::OutputLimitExceeded
        )
    );
    assert!(matches!(
        check.status(),
        runne_provider::ProviderRemoteResponseStatus::Completed { usage: Some(_) }
    ));
    assert!(RemoteResponseId::new("resp_a/../../b").is_ok());
    assert!(
        OpenAiBackgroundResponse::from_json(br#"{"id":"resp_a/../../b","status":"queued"}"#)
            .is_err()
    );
}

#[test]
fn missing_non_success_usage_remains_absent_for_conservative_accounting() {
    for status in ["failed", "incomplete", "cancelled"] {
        let item = terminal(status, None);
        assert!(match item.status() {
            runne_provider::ProviderRemoteResponseStatus::Failed { usage, .. }
            | runne_provider::ProviderRemoteResponseStatus::Incomplete { usage, .. }
            | runne_provider::ProviderRemoteResponseStatus::Cancelled { usage } => usage.is_none(),
            _ => false,
        });
    }
}
