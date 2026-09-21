#![allow(dead_code, clippy::needless_pass_by_value)]
use runne_provider::{
    DispatchAttemptId, DispatchRequest, ModelRef, PreparedRequest, ProviderCall, ProviderCallId,
    ProviderCapability, ProviderDispatchClaim, ProviderId, ProviderInputRole, ProviderTextInput,
};
use runne_provider_deepseek::{
    DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DeepSeekResponsesTextProfile,
};
use serde_json::{Value, json};

pub const RESPONSE_ID: &str = "resp_runne_exact";
pub const ITEM_ID: &str = "msg_runne_exact";
pub const PROFILE_BYTES: &[u8] =
    include_bytes!("../../../../docs/profiles/deepseek-responses-text-v1.json");

pub fn profile() -> DeepSeekResponsesTextProfile {
    DeepSeekResponsesTextProfile::from_json(PROFILE_BYTES).expect("exact DeepSeek profile")
}

pub fn call(profile: &DeepSeekResponsesTextProfile) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").expect("provider id"),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .expect("model ref"),
        [9; 32],
        32,
        profile.binding_extension(),
    )
    .expect("provider call")
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").expect("text input"),
    ])
    .expect("text inputs")
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

pub fn dispatch_request(
    prepared: PreparedRequest,
    attempt_id: DispatchAttemptId,
    request_id: &str,
    profile: &DeepSeekResponsesTextProfile,
) -> DispatchRequest {
    let claim = ProviderDispatchClaim {
        provider_id: ProviderId::new("deepseek").expect("provider id"),
        call_id: prepared.call().call_id(),
        attempt_id,
        permit_id: [4; 16],
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: profile.profile_digest(),
        token_reservation_id: [5; 16],
        cost_reservation_id: [6; 16],
        fencing_token: 1,
        provider_idempotency_key: request_id.to_owned(),
    };
    DispatchRequest::new(prepared, claim).expect("dispatch request")
}

pub fn event(sequence: u64, value: Value) -> String {
    let event_type = value
        .get("type")
        .and_then(Value::as_str)
        .expect("event type");
    format!(
        "event: {event_type}\ndata: {}\n\n",
        serde_json::to_string(
            &value
                .as_object()
                .map(|object| {
                    let mut object = object.clone();
                    object.insert("sequence_number".to_owned(), json!(sequence));
                    Value::Object(object)
                })
                .expect("event object")
        )
        .expect("event JSON")
    )
}

pub fn response(status: &str, output: Value, usage: Value) -> Value {
    json!({
        "id": RESPONSE_ID,
        "model": runne_provider_deepseek::DEEPSEEK_REQUEST_MODEL,
        "object": "response",
        "status": status,
        "output": output,
        "usage": usage,
        "error": if status == "failed" {
            json!({"code": "server_error", "message": "remote diagnostic must be redacted"})
        } else {
            Value::Null
        },
        "incomplete_details": if status == "incomplete" {
            json!({"reason": "max_output_tokens"})
        } else {
            Value::Null
        }
    })
}

pub fn added_item() -> Value {
    json!({
        "id": ITEM_ID,
        "type": "message",
        "status": "in_progress",
        "role": "assistant",
        "content": []
    })
}

pub fn completed_item(text: &str, status: &str) -> Value {
    json!({
        "id": ITEM_ID,
        "type": "message",
        "status": status,
        "role": "assistant",
        "content": [{
            "type": "output_text",
            "text": text,
            "annotations": []
        }]
    })
}

pub fn added_part() -> Value {
    json!({"type": "output_text", "text": "", "annotations": []})
}

pub fn completed_part(text: &str) -> Value {
    json!({"type": "output_text", "text": text, "annotations": []})
}

pub fn successful_sse() -> Vec<u8> {
    let mut body = String::new();
    body.push_str(&event(
        0,
        json!({"type": "response.created", "response": response("in_progress", json!([]), Value::Null)}),
    ));
    body.push_str(&event(
        1,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), Value::Null)}),
    ));
    body.push_str(&event(
        2,
        json!({"type": "response.output_item.added", "output_index": 0, "item": added_item()}),
    ));
    body.push_str(&event(
        3,
        json!({
            "type": "response.content_part.added",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": added_part()
        }),
    ));
    body.push_str(&event(
        4,
        json!({
            "type": "response.output_text.delta",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "delta": "Привет, "
        }),
    ));
    body.push_str(&event(
        5,
        json!({
            "type": "response.output_text.delta",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "delta": "world"
        }),
    ));
    body.push_str(&event(
        6,
        json!({
            "type": "response.output_text.done",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "text": "Привет, world"
        }),
    ));
    body.push_str(&event(
        7,
        json!({
            "type": "response.content_part.done",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": completed_part("Привет, world")
        }),
    ));
    body.push_str(&event(
        8,
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": completed_item("Привет, world", "completed")
        }),
    ));
    body.push_str(&event(
        9,
        json!({
            "type": "response.completed",
            "response": response(
                "completed",
                json!([completed_item("Привет, world", "completed")]),
                json!({
                    "input_tokens": 11,
                    "input_tokens_details": {"cached_tokens": 3},
                    "output_tokens": 4,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 15
                })
            )
        }),
    ));
    body.into_bytes()
}

pub fn failed_sse() -> Vec<u8> {
    event(
        0,
        json!({
            "type": "response.failed",
            "response": response("failed", json!([]), Value::Null)
        }),
    )
    .into_bytes()
}

pub fn incomplete_sse() -> Vec<u8> {
    let mut body = String::new();
    body.push_str(&event(
        0,
        json!({"type": "response.created", "response": response("in_progress", json!([]), Value::Null)}),
    ));
    body.push_str(&event(
        1,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), Value::Null)}),
    ));
    body.push_str(&event(
        2,
        json!({"type": "response.output_item.added", "output_index": 0, "item": added_item()}),
    ));
    body.push_str(&event(
        3,
        json!({
            "type": "response.content_part.added",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": added_part()
        }),
    ));
    body.push_str(&event(
        4,
        json!({
            "type": "response.output_text.delta",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "delta": "partial"
        }),
    ));
    body.push_str(&event(
        5,
        json!({
            "type": "response.incomplete",
            "response": response(
                "incomplete",
                json!([completed_item("partial", "incomplete")]),
                Value::Null
            )
        }),
    ));
    body.into_bytes()
}

pub fn standalone_error_sse() -> Vec<u8> {
    event(
        0,
        json!({
            "type": "error",
            "code": "server_error",
            "message": "raw remote error must never escape",
            "param": null
        }),
    )
    .into_bytes()
}
