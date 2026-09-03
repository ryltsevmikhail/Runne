#![allow(dead_code, clippy::needless_pass_by_value)]

use serde_json::{Value, json};

pub const SECRET: &[u8] = b"fixture-secret-never-log";
pub const RESPONSE_ID: &str = "resp_runne_conformance";
pub const ITEM_ID: &str = "msg_runne_conformance";

pub fn event(sequence: u64, value: Value) -> String {
    let event_type = value
        .get("type")
        .and_then(Value::as_str)
        .expect("event type");
    let mut object = value.as_object().expect("event object").clone();
    object.insert("sequence_number".into(), json!(sequence));
    format!(
        "event: {event_type}\ndata: {}\n\n",
        serde_json::to_string(&object).expect("event JSON")
    )
}

pub fn response(model: &str, tier: &str, status: &str, output: Value, usage: Value) -> Value {
    json!({
        "id": RESPONSE_ID,
        "model": model,
        "object": "response",
        "service_tier": tier,
        "status": status,
        "output": output,
        "usage": usage,
        "error": Value::Null,
        "incomplete_details": Value::Null
    })
}

fn added_item() -> Value {
    json!({"id": ITEM_ID, "type": "message", "status": "in_progress", "role": "assistant", "content": []})
}

fn completed_item(text: &str) -> Value {
    json!({"id": ITEM_ID, "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": text, "annotations": []}]})
}

pub fn successful_sse(model: &str, tier: &str) -> Vec<u8> {
    let text = "hello world";
    let mut body = String::new();
    body.push_str(&event(0, json!({"type": "response.created", "response": response(model, tier, "in_progress", json!([]), Value::Null)})));
    body.push_str(&event(1, json!({"type": "response.in_progress", "response": response(model, tier, "in_progress", json!([]), Value::Null)})));
    body.push_str(&event(
        2,
        json!({"type": "response.output_item.added", "output_index": 0, "item": added_item()}),
    ));
    body.push_str(&event(3, json!({"type": "response.content_part.added", "item_id": ITEM_ID, "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}})));
    body.push_str(&event(4, json!({"type": "response.output_text.delta", "item_id": ITEM_ID, "output_index": 0, "content_index": 0, "delta": "hello "})));
    body.push_str(&event(5, json!({"type": "response.output_text.delta", "item_id": ITEM_ID, "output_index": 0, "content_index": 0, "delta": "world"})));
    body.push_str(&event(6, json!({"type": "response.output_text.done", "item_id": ITEM_ID, "output_index": 0, "content_index": 0, "text": text})));
    body.push_str(&event(7, json!({"type": "response.content_part.done", "item_id": ITEM_ID, "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": text, "annotations": []}})));
    body.push_str(&event(8, json!({"type": "response.output_item.done", "output_index": 0, "item": completed_item(text)})));
    body.push_str(&event(9, json!({"type": "response.completed", "response": response(model, tier, "completed", json!([completed_item(text)]), json!({"input_tokens": 2, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 2, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 4}))})));
    body.into_bytes()
}

pub fn split_bytes(bytes: &[u8], width: usize) -> Vec<Vec<u8>> {
    bytes.chunks(width).map(ToOwned::to_owned).collect()
}

pub fn rejection() -> Vec<u8> {
    br#"{"error":{"code":"authentication_failed","message":"redacted diagnostic","type":"auth_error","param":null}}"#.to_vec()
}
