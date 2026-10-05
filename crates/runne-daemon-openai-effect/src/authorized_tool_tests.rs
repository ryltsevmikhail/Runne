use runne_provider::DispatchAttemptId;
use runne_provider_openai::{OpenAiResponsesToolProfile, OpenAiTransportResponse};
use serde_json::{Value, json};

#[test]
fn authorized_tool_binding_uses_tool_digest_and_tool_response_decoder() {
    let text_profile = super::profile().unwrap();
    let tool_profile = OpenAiResponsesToolProfile::new(text_profile.clone()).unwrap();
    let sender = super::Sender::new(
        text_profile,
        super::client::FixtureCredential::new(),
        reqwest::Client::new(),
    )
    .unwrap();
    assert_eq!(
        sender.expected_profile_digest(true),
        Some(tool_profile.profile_digest())
    );
    assert_ne!(
        sender.expected_profile_digest(true),
        sender.expected_profile_digest(false)
    );

    let call = json!({"id":"fc_1","type":"function_call","status":"completed",
        "call_id":"call_1","name":"workspace_file_read","arguments":"{\"path\":\"a.txt\"}"});
    let events = [
        json!({"type":"response.created","response":response("in_progress",json!([]),Value::Null)}),
        json!({"type":"response.in_progress","response":response("in_progress",json!([]),Value::Null)}),
        json!({"type":"response.output_item.added","output_index":0,"item":{
            "id":"fc_1","type":"function_call","status":"in_progress","call_id":"call_1",
            "name":"workspace_file_read","arguments":""}}),
        json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_1","delta":"{\"path\":\"a.txt\"}"}),
        json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"fc_1","arguments":"{\"path\":\"a.txt\"}"}),
        json!({"type":"response.output_item.done","output_index":0,"item":call.clone()}),
        json!({"type":"response.completed","response":response("completed",json!([call]),json!({
            "input_tokens":2,"input_tokens_details":{"cached_tokens":0},"output_tokens":2,
            "output_tokens_details":{"reasoning_tokens":0},"total_tokens":4}))}),
    ];
    let body = events
        .iter()
        .enumerate()
        .map(|(index, event)| frame(index, event))
        .collect::<String>();
    let transport = OpenAiTransportResponse::sse(vec![body.into_bytes()]).unwrap();
    assert!(
        sender
            .store_response(DispatchAttemptId::from_bytes([3; 16]), transport, true)
            .is_ok()
    );
}

fn frame(sequence: usize, value: &Value) -> String {
    let mut value = value.as_object().unwrap().clone();
    value.insert("sequence_number".into(), json!(sequence));
    let event_type = value["type"].as_str().unwrap().to_owned();
    format!("event: {event_type}\ndata: {}\n\n", Value::Object(value))
}

fn response(status: &str, output: Value, usage: Value) -> Value {
    json!({"id":"resp_1","object":"response","model":"gpt-5.5-2026-04-23",
        "service_tier":"default","status":status,"output":output,"usage":usage,
        "error":null,"incomplete_details":null})
}
