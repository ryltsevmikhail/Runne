mod support;

use runne_provider::{ProviderFinishReason, ProviderStreamEventKind};
use runne_provider_openai::{
    OpenAiResponsesTextProfile, OpenAiResponsesToolProfile, OpenAiSseDecoder, OpenAiStreamError,
};
use serde_json::{Value, json};
use support::{PROFILE_BYTES, event, response};

fn profile() -> OpenAiResponsesToolProfile {
    OpenAiResponsesToolProfile::new(OpenAiResponsesTextProfile::from_json(PROFILE_BYTES).unwrap())
        .unwrap()
}

fn item(name: &str, args: &str, status: &str) -> Value {
    json!({
        "id":"fc_item_1", "type":"function_call", "status":status,
        "call_id":"call_1", "name":name, "arguments":args
    })
}

fn tool_stream(name: &str, args: &str) -> Vec<u8> {
    let mut body = String::new();
    body.push_str(&event(
        0,
        json!({"type":"response.created","response":response("in_progress",json!([]),Value::Null)}),
    ));
    body.push_str(&event(1, json!({"type":"response.in_progress","response":response("in_progress",json!([]),Value::Null)})));
    body.push_str(&event(2, json!({"type":"response.output_item.added","output_index":0,"item":item(name,"","in_progress")})));
    let split = args.len() / 2;
    let (left, right) = args.split_at(split);
    body.push_str(&event(3, json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_item_1","delta":left})));
    body.push_str(&event(4, json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_item_1","delta":right})));
    body.push_str(&event(5, json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"fc_item_1","arguments":args})));
    body.push_str(&event(6, json!({"type":"response.output_item.done","output_index":0,"item":item(name,args,"completed")})));
    body.push_str(&event(
        7,
        json!({
            "type":"response.completed",
            "response":response("completed",json!([item(name,args,"completed")]),json!({
                "input_tokens":12,"input_tokens_details":{"cached_tokens":0},
                "output_tokens":4,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":16
            }))
        }),
    ));
    body.into_bytes()
}

#[test]
fn decoder_normalizes_complete_read_and_create_calls_with_usage() {
    for (name, args, normalized) in [
        (
            "workspace_file_read",
            r#"{"path":"notes.txt"}"#,
            "workspace.file.read",
        ),
        (
            "workspace_file_create_new",
            r#"{"path":"new.txt","content_base64":"aGk="}"#,
            "workspace.file.create_new",
        ),
    ] {
        let profile = profile();
        let mut decoder = OpenAiSseDecoder::for_tool_profile(&profile);
        decoder.push(&tool_stream(name, args)).unwrap();
        let events = decoder.finish().unwrap();
        assert!(
            matches!(events[1].kind(), ProviderStreamEventKind::ToolCallRequested {
            call_id, tool_name, arguments_json
        } if call_id == "call_1" && tool_name == normalized && arguments_json == args)
        );
        assert!(matches!(
            events.last().unwrap().kind(),
            ProviderStreamEventKind::Finished {
                reason: ProviderFinishReason::ToolCalls,
                ..
            }
        ));
    }
}

#[test]
fn decoder_fails_closed_on_unknown_multiple_truncated_or_reasoning_items() {
    let profile = profile();
    let mut unknown = OpenAiSseDecoder::for_tool_profile(&profile);
    assert_eq!(
        unknown.push(&tool_stream("workspace_file_delete", "{}")),
        Err(OpenAiStreamError::UnknownEvent)
    );

    let mut truncated_body = String::new();
    truncated_body.push_str(&event(
        0,
        json!({"type":"response.created","response":response("in_progress",json!([]),Value::Null)}),
    ));
    truncated_body.push_str(&event(1, json!({"type":"response.in_progress","response":response("in_progress",json!([]),Value::Null)})));
    truncated_body.push_str(&event(2, json!({"type":"response.output_item.added","output_index":0,"item":item("workspace_file_read","","in_progress")})));
    truncated_body.push_str(&event(3, json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_item_1","delta":"{}"})));
    truncated_body.push_str(&event(4, json!({"type":"response.output_item.done","output_index":0,"item":item("workspace_file_read","{}","completed")})));
    let mut truncated = OpenAiSseDecoder::for_tool_profile(&profile);
    assert_eq!(
        truncated.push(truncated_body.as_bytes()),
        Err(OpenAiStreamError::IllegalTransition)
    );

    let mut reasoning = OpenAiSseDecoder::for_tool_profile(&profile);
    let reasoning_frame = event(
        0,
        json!({"type":"response.output_item.added","output_index":0,"item":{"id":"reason_1","type":"reasoning","status":"in_progress","summary":[]}}),
    );
    assert_eq!(
        reasoning.push(reasoning_frame.as_bytes()),
        Err(OpenAiStreamError::IllegalTransition)
    );

    let mut multiple = OpenAiSseDecoder::for_tool_profile(&profile);
    let multiple_frame = event(
        0,
        json!({"type":"response.output_item.added","output_index":1,"item":item("workspace_file_read","","in_progress")}),
    );
    assert_eq!(
        multiple.push(multiple_frame.as_bytes()),
        Err(OpenAiStreamError::IllegalTransition)
    );
}
