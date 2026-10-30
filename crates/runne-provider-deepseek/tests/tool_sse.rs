mod support;

use runne_provider::{ProviderFinishReason, ProviderStreamEventKind};
use runne_provider_deepseek::{
    DeepSeekResponsesTextProfile, DeepSeekResponsesToolProfile, DeepSeekSseDecoder,
    DeepSeekStreamError,
};
use serde_json::{Value, json};
use support::{PROFILE_BYTES, event, response};

fn profile() -> DeepSeekResponsesToolProfile {
    DeepSeekResponsesToolProfile::new(
        DeepSeekResponsesTextProfile::from_json(PROFILE_BYTES).unwrap(),
    )
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
        let mut decoder = DeepSeekSseDecoder::for_tool_profile(&profile);
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
    let mut unknown = DeepSeekSseDecoder::for_tool_profile(&profile);
    assert_eq!(
        unknown.push(&tool_stream("workspace_file_delete", "{}")),
        Err(DeepSeekStreamError::UnknownEvent)
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
    let mut truncated = DeepSeekSseDecoder::for_tool_profile(&profile);
    assert_eq!(
        truncated.push(truncated_body.as_bytes()),
        Err(DeepSeekStreamError::IllegalTransition)
    );

    let mut reasoning = DeepSeekSseDecoder::for_tool_profile(&profile);
    let reasoning_frame = event(
        0,
        json!({"type":"response.output_item.added","output_index":0,"item":{"id":"reason_1","type":"reasoning","status":"in_progress","summary":[]}}),
    );
    assert_eq!(
        reasoning.push(reasoning_frame.as_bytes()),
        Err(DeepSeekStreamError::IllegalTransition)
    );

    let mut multiple = DeepSeekSseDecoder::for_tool_profile(&profile);
    let multiple_frame = event(
        0,
        json!({"type":"response.output_item.added","output_index":1,"item":item("workspace_file_read","","in_progress")}),
    );
    assert_eq!(
        multiple.push(multiple_frame.as_bytes()),
        Err(DeepSeekStreamError::IllegalTransition)
    );
}
#[test]
fn tool_evidence_rejects_tampering_and_text_profile_stays_closed() {
    let original = tool_stream("workspace_file_read", r#"{"path":"notes.txt"}"#);
    let wire = String::from_utf8(original.clone()).unwrap();
    for (from, to) in [
        (
            r#""arguments":"{\"path\":\"notes.txt\"}""#,
            r#""arguments":"{}""#,
        ),
        (r#""item_id":"fc_item_1""#, r#""item_id":"wrong""#),
        (r#""output_index":0"#, r#""output_index":1"#),
        (r#""total_tokens":16"#, r#""total_tokens":17"#),
    ] {
        let changed = wire.replacen(from, to, 1);
        assert_ne!(changed, wire);
        let mut decoder = DeepSeekSseDecoder::for_tool_profile(&profile());
        assert!(
            decoder
                .push(changed.as_bytes())
                .and_then(|()| decoder.finish())
                .is_err()
        );
    }
    let mut text = DeepSeekSseDecoder::default();
    assert!(text.push(&original).is_err());
    for chunk_size in [1, 7, 256] {
        let mut decoder = DeepSeekSseDecoder::for_tool_profile(&profile());
        for chunk in original.chunks(chunk_size) {
            decoder.push(chunk).unwrap();
        }
        assert!(decoder.finish().is_ok());
    }
}
#[test]
fn repeated_calls_are_bounded_and_call_ids_are_unique() {
    let original = String::from_utf8(tool_stream("workspace_file_read", "{}")).unwrap();
    let frames: Vec<Value> = original
        .split("\n\n")
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(s.split_once("data: ").unwrap().1).unwrap())
        .collect();
    for count in [2, 16, 17] {
        let mut events = frames[..2].to_vec();
        let mut output = Vec::new();
        for index in 0..count {
            for source in &frames[2..7] {
                let mut value = source.clone();
                value["output_index"] = json!(index);
                if value.get("item_id").is_some() {
                    value["item_id"] = json!(format!("item_{index}"));
                }
                if let Some(item) = value.get_mut("item") {
                    item["id"] = json!(format!("item_{index}"));
                    item["call_id"] = json!(format!("call_{index}"));
                    if item["status"] == "completed" {
                        output.push(item.clone());
                    }
                }
                events.push(value);
            }
        }
        let mut terminal = frames[7].clone();
        terminal["response"]["output"] = json!(output);
        events.push(terminal);
        let body: String = events
            .into_iter()
            .enumerate()
            .map(|(i, v)| event(i as u64, v))
            .collect();
        let mut decoder = DeepSeekSseDecoder::for_tool_profile(&profile());
        let result = decoder
            .push(body.as_bytes())
            .and_then(|()| decoder.finish());
        assert_eq!(result.is_ok(), count <= 16);
        if count == 2 {
            let duplicate = body.replace("call_1", "call_0");
            let mut decoder = DeepSeekSseDecoder::for_tool_profile(&profile());
            assert!(decoder.push(duplicate.as_bytes()).is_err());
        }
    }
}
#[test]
fn scripted_tool_response_result_followup_and_final_text_roundtrip() {
    use runne_provider::{
        ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
        ProviderTextInput, ProviderToolNameV1, ProviderToolResultV1, TextProviderProfile,
        ToolProviderProfile,
    };
    use runne_provider_deepseek::{
        DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DeepSeekResponsesToolRenderer,
    };
    let profile = profile();
    let mut results = Vec::new();
    for (index, (name, args)) in [
        ("workspace_files_list", r#"{"path":".","limit":20}"#),
        ("workspace_file_read", r#"{"path":"notes.txt"}"#),
        (
            "workspace_command_run",
            r#"{"cwd":".","argv":["true"],"timeout_ms":1000}"#,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let body = String::from_utf8(tool_stream(name, args))
            .unwrap()
            .replace("call_1", &format!("call_{index}"));
        let mut decoder = DeepSeekSseDecoder::for_tool_profile(&profile);
        decoder.push(body.as_bytes()).unwrap();
        let events = decoder.finish().unwrap();
        let ProviderStreamEventKind::ToolCallRequested {
            call_id,
            arguments_json,
            ..
        } = events[1].kind()
        else {
            panic!("tool proposal")
        };
        results.push(
            ProviderToolResultV1::new(
                call_id.clone(),
                ProviderToolNameV1::from_wire_name(name).unwrap(),
                arguments_json.clone(),
                r#"{"fixture_result":"completed"}"#.to_owned(),
            )
            .unwrap(),
        );
        let call = ProviderCall::new(
            ProviderCallId::from_bytes([7; 16]),
            ModelRef::new(
                ProviderId::new("deepseek").unwrap(),
                DEEPSEEK_MODEL_ID,
                DEEPSEEK_MODEL_REVISION,
            )
            .unwrap(),
            [9; 32],
            256,
            profile.call_binding_extension(),
        )
        .unwrap()
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "inspect and verify").unwrap(),
        ])
        .unwrap()
        .with_tool_context(profile.tool_declarations().to_vec(), results.clone())
        .unwrap()
        .with_required_capabilities(vec![
            ProviderCapability::Streaming,
            ProviderCapability::Tools,
        ]);
        let prepared = DeepSeekResponsesToolRenderer::new(profile.clone())
            .prepare(&call)
            .unwrap();
        let request: Value = serde_json::from_slice(prepared.rendered_bytes()).unwrap();
        for (i, result) in results.iter().enumerate() {
            assert_eq!(request["input"][1 + i * 2]["call_id"], result.call_id());
            assert_eq!(request["input"][2 + i * 2]["call_id"], result.call_id());
            assert_eq!(request["input"][2 + i * 2]["output"], result.output());
        }
    }
    let mut decoder = DeepSeekSseDecoder::for_tool_profile(&profile);
    decoder.push(&support::successful_sse()).unwrap();
    let events = decoder.finish().unwrap();
    assert!(matches!(
        events.last().unwrap().kind(),
        ProviderStreamEventKind::Finished {
            reason: ProviderFinishReason::Stop,
            ..
        }
    ));
}
