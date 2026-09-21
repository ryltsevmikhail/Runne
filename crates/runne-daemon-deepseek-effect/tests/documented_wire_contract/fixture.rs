use serde_json::{Value, json};

pub(super) enum WireResponse {
    Sse(String),
    JsonRejection(u16, String),
    ChatDone,
}

fn frame(sequence: u64, value: Value) -> String {
    let event_type = value["type"].as_str().expect("event type").to_owned();
    let mut object = value.as_object().expect("event object").clone();
    object.insert("sequence_number".to_owned(), json!(sequence));
    format!(
        "event: {event_type}\ndata: {}\n\n",
        serde_json::to_string(&Value::Object(object)).unwrap()
    )
}

fn documented_response(status: &str, output: Value, usage: Value) -> Value {
    json!({
        "id": "resp_documented",
        "object": "response",
        "model": "deepseek-flash",
        "status": status,
        "output": output,
        "usage": usage,
        "error": if status == "failed" {
            json!({"code": "server_error", "message": "remote diagnostic"})
        } else {
            Value::Null
        },
        "incomplete_details": Value::Null,
    })
}

fn message_item(text: &str, status: &str) -> Value {
    json!({
        "type": "message",
        "id": "msg_documented",
        "status": status,
        "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    })
}

pub(super) fn documented_sse() -> String {
    let empty_output = json!([]);
    let null_usage = Value::Null;
    let mut wire = String::new();
    wire.push_str(&frame(
        0,
        json!({"type": "response.created", "response": documented_response("in_progress", empty_output.clone(), null_usage.clone())}),
    ));
    wire.push_str(&frame(
        2,
        json!({"type": "response.in_progress", "response": documented_response("in_progress", empty_output.clone(), null_usage.clone())}),
    ));
    wire.push_str(&frame(
        4,
        json!({"type": "response.output_item.added", "output_index": 0, "item": {
            "type": "message", "id": "msg_documented", "status": "in_progress",
            "role": "assistant", "content": [],
        }}),
    ));
    wire.push_str(&documented_item_frames());
    wire
}

pub(super) fn documented_sse_without_in_progress() -> String {
    let empty_output = json!([]);
    let null_usage = Value::Null;
    let mut wire = String::new();
    wire.push_str(&frame(
        0,
        json!({"type": "response.created", "response": documented_response("in_progress", empty_output, null_usage)}),
    ));
    wire.push_str(&frame(
        1,
        json!({"type": "response.output_item.added", "output_index": 0, "item": {
            "type": "message", "id": "msg_documented", "status": "in_progress",
            "role": "assistant", "content": [],
        }}),
    ));
    wire.push_str(&documented_item_frames());
    wire
}

fn documented_item_frames() -> String {
    let mut wire = String::new();
    wire.push_str(&frame(
        5,
        json!({"type": "response.content_part.added", "item_id": "msg_documented", "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": "", "annotations": []}}),
    ));
    wire.push_str(&frame(
        7,
        json!({"type": "response.output_text.delta", "item_id": "msg_documented", "output_index": 0, "content_index": 0, "delta": "Привет, "}),
    ));
    wire.push_str(&frame(
        9,
        json!({"type": "response.output_text.delta", "item_id": "msg_documented", "output_index": 0, "content_index": 0, "delta": "world"}),
    ));
    wire.push_str(&frame(
        11,
        json!({"type": "response.output_text.done", "item_id": "msg_documented", "output_index": 0, "content_index": 0, "text": "Привет, world"}),
    ));
    wire.push_str(&frame(
        13,
        json!({"type": "response.content_part.done", "item_id": "msg_documented", "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": "Привет, world", "annotations": []}}),
    ));
    wire.push_str(&frame(
        14,
        json!({"type": "response.output_item.done", "output_index": 0, "item": message_item("Привет, world", "completed")}),
    ));
    wire.push_str(&frame(
        20,
        json!({"type": "response.completed", "response": documented_response(
            "completed",
            json!([message_item("Привет, world", "completed")]),
            json!({
                "input_tokens": 11,
                "input_tokens_details": {"cached_tokens": 3},
                "output_tokens": 4,
                "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": 15,
            }),
        )}),
    ));
    wire
}
