use serde_json::{Value, json};
use sha2::{Digest, Sha256};
fn event(sequence: u64, mut value: Value) -> String {
    value["sequence_number"] = json!(sequence);
    format!(
        "event: {}\ndata: {}\n\n",
        value["type"].as_str().unwrap(),
        value
    )
}
fn response(status: &str, output: Value, usage: Value) -> Value {
    json!({"id":"resp_terminal_fixture","object":"response","model":runne_provider_deepseek::DEEPSEEK_REQUEST_MODEL,"status":status,"output":output,"usage":usage,"error":null,"incomplete_details":null})
}
fn usage() -> Value {
    json!({"input_tokens":12,"input_tokens_details":{"cached_tokens":0},"output_tokens":4,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":16})
}
pub(super) fn body(request: &Value) -> Result<String, ()> {
    let inputs = request["input"].as_array().ok_or(())?;
    let results = inputs
        .iter()
        .filter(|item| item["type"] == "function_call_output")
        .count();
    let zero = request.to_string().contains("terminal:zero");
    let calls = if zero {
        vec![]
    } else if request.to_string().contains("terminal:timeout") {
        if results == 0 {
            vec![(
                "workspace_command_run",
                json!({"cwd":".","argv":["/bin/sh","-c","sleep 2; printf leaked > late.txt"],"timeout_ms":50}),
            )]
        } else {
            vec![]
        }
    } else if request.to_string().contains("terminal:deny") {
        vec![(
            "workspace_file_create_new",
            json!({"path":"denied.txt","content_base64":"bm90IGFsbG93ZWQ="}),
        )]
    } else {
        match results {
            0 => vec![
                ("workspace_files_list", json!({"path":".","limit":20})),
                ("workspace_file_read", json!({"path":"notes.txt"})),
            ],
            2 => vec![(
                "workspace_file_replace",
                json!({"path":"notes.txt","expected_sha256":format!("{:x}",Sha256::digest(b"before\n")),"content_base64":"YWZ0ZXIK"}),
            )],
            3 => vec![(
                "workspace_command_run",
                json!({"cwd":".","argv":["/bin/sh","-c","pwd && printf terminal-command-ok"],"timeout_ms":1000}),
            )],
            4 => vec![(
                "workspace_files_search",
                json!({"path":".","query":"after","limit":10}),
            )],
            5 => vec![(
                "workspace_file_create_new",
                json!({"path":"created.txt","content_base64":"Y3JlYXRlZAo="}),
            )],
            6 => vec![],
            _ => return Err(()),
        }
    };
    let mut output = event(
        0,
        json!({"type":"response.created","response":response("in_progress",json!([]),Value::Null)}),
    );
    output += &event(
        1,
        json!({"type":"response.in_progress","response":response("in_progress",json!([]),Value::Null)}),
    );
    let mut sequence = 2;
    if calls.is_empty() {
        let part = json!({"type":"output_text","text":"","annotations":[]});
        output += &event(
            sequence,
            json!({"type":"response.output_item.added","output_index":0,"item":{"id":"msg_terminal","type":"message","role":"assistant","status":"in_progress","content":[]}}),
        );
        sequence += 1;
        output += &event(
            sequence,
            json!({"type":"response.content_part.added","item_id":"msg_terminal","output_index":0,"content_index":0,"part":part}),
        );
        sequence += 1;
        output += &event(
            sequence,
            json!({"type":"response.output_text.delta","item_id":"msg_terminal","output_index":0,"content_index":0,"delta":"OK"}),
        );
        sequence += 1;
        output += &event(
            sequence,
            json!({"type":"response.output_text.done","item_id":"msg_terminal","output_index":0,"content_index":0,"text":"OK"}),
        );
        sequence += 1;
        let part = json!({"type":"output_text","text":"OK","annotations":[]});
        output += &event(
            sequence,
            json!({"type":"response.content_part.done","item_id":"msg_terminal","output_index":0,"content_index":0,"part":part}),
        );
        sequence += 1;
        let item = json!({"id":"msg_terminal","type":"message","role":"assistant","status":"completed","content":[part]});
        output += &event(
            sequence,
            json!({"type":"response.output_item.done","output_index":0,"item":item}),
        );
        sequence += 1;
        output += &event(
            sequence,
            json!({"type":"response.completed","response":response("completed",json!([item]),usage())}),
        );
    } else {
        let mut items = Vec::new();
        for (index, (name, args)) in calls.into_iter().enumerate() {
            let id = format!("fc_terminal_{}", results + index);
            let call = format!("call_terminal_{}", results + index);
            let args = args.to_string();
            output += &event(
                sequence,
                json!({"type":"response.output_item.added","output_index":index,"item":{"id":id,"type":"function_call","status":"in_progress","call_id":call,"name":name,"arguments":""}}),
            );
            sequence += 1;
            output += &event(
                sequence,
                json!({"type":"response.function_call_arguments.delta","output_index":index,"item_id":id,"delta":args}),
            );
            sequence += 1;
            output += &event(
                sequence,
                json!({"type":"response.function_call_arguments.done","output_index":index,"item_id":id,"arguments":args}),
            );
            sequence += 1;
            let item = json!({"id":id,"type":"function_call","status":"completed","call_id":call,"name":name,"arguments":args});
            output += &event(
                sequence,
                json!({"type":"response.output_item.done","output_index":index,"item":item}),
            );
            sequence += 1;
            items.push(item);
        }
        output += &event(
            sequence,
            json!({"type":"response.completed","response":response("completed",json!(items),usage())}),
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider_deepseek::*;
    #[test]
    fn every_synthetic_round_uses_admitted_wire_tool_names() {
        let text = DeepSeekResponsesTextProfile::from_json(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/profiles/deepseek-responses-text-v1.json"
        )))
        .unwrap();
        let profile = DeepSeekResponsesToolProfile::new(text).unwrap();
        for (mode, count) in [
            ("tools", 0),
            ("tools", 2),
            ("tools", 3),
            ("tools", 4),
            ("tools", 5),
            ("tools", 6),
            ("deny", 0),
            ("timeout", 0),
            ("timeout", 1),
            ("zero", 0),
        ] {
            let input = (0..count)
                .map(|_| json!({"type":"function_call_output"}))
                .collect::<Vec<_>>();
            let wire =
                body(&json!({"input":input,"fixture_mode":format!("terminal:{mode}")})).unwrap();
            let mut decoder = DeepSeekSseDecoder::for_tool_profile(&profile);
            decoder.push(wire.as_bytes()).unwrap();
            decoder.finish().unwrap();
        }
    }
}
