mod support;

use gocode_provider::{ProviderFinishReason, ProviderStreamEventKind, ProviderTerminalDisposition};
use gocode_provider_openai::{
    OPENAI_MAX_SSE_EVENTS, OPENAI_MAX_SSE_LINES, OPENAI_REQUEST_MODEL, OPENAI_SERVICE_TIER,
    OpenAiSseDecoder, OpenAiStreamError,
};
use serde_json::json;

use support::{
    ITEM_ID, RESPONSE_ID, added_item, added_part, completed_item, completed_part, event,
    failed_sse, incomplete_sse, response, standalone_error_sse, successful_sse,
};

fn decode(bytes: &[u8]) -> Result<Vec<gocode_provider::ProviderStreamEvent>, OpenAiStreamError> {
    let mut decoder = OpenAiSseDecoder::default();
    decoder.push(bytes)?;
    decoder.finish()
}

#[test]
fn complete_official_lifecycle_normalizes_only_text_usage_and_terminal() {
    let events = decode(&successful_sse()).expect("successful stream");
    assert_eq!(events.len(), 5);
    assert!(matches!(events[0].kind(), ProviderStreamEventKind::Started));
    assert_eq!(
        events[1].kind(),
        &ProviderStreamEventKind::TextDelta {
            text: "Привет, ".to_owned()
        }
    );
    assert_eq!(
        events[2].kind(),
        &ProviderStreamEventKind::TextDelta {
            text: "world".to_owned()
        }
    );
    let ProviderStreamEventKind::Usage { usage } = events[3].kind() else {
        panic!("expected usage");
    };
    assert_eq!(usage.input_tokens(), 11);
    assert_eq!(usage.cached_input_tokens(), 3);
    assert_eq!(usage.output_tokens(), 4);
    assert_eq!(usage.reasoning_output_tokens(), 0);
    assert_eq!(
        events[4].kind(),
        &ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop
        }
    );
}

#[test]
fn failed_incomplete_and_first_frame_error_are_closed_terminal_branches() {
    for (body, disposition, reason, has_partial_text) in [
        (
            failed_sse(),
            ProviderTerminalDisposition::RemoteFailed,
            ProviderFinishReason::Error,
            false,
        ),
        (
            incomplete_sse(),
            ProviderTerminalDisposition::RemoteIncomplete,
            ProviderFinishReason::Length,
            true,
        ),
        (
            standalone_error_sse(),
            ProviderTerminalDisposition::RemoteFailed,
            ProviderFinishReason::Error,
            false,
        ),
    ] {
        let events = decode(&body).expect("legal terminal branch");
        assert!(matches!(
            events
                .first()
                .map(gocode_provider::ProviderStreamEvent::kind),
            Some(ProviderStreamEventKind::Started)
        ));
        assert_eq!(
            events
                .iter()
                .any(|event| matches!(event.kind(), ProviderStreamEventKind::TextDelta { .. })),
            has_partial_text
        );
        assert!(matches!(
            events
                .get(events.len() - 2)
                .map(gocode_provider::ProviderStreamEvent::kind),
            Some(ProviderStreamEventKind::UsageUnavailable)
        ));
        assert_eq!(
            events
                .last()
                .map(gocode_provider::ProviderStreamEvent::kind),
            Some(&ProviderStreamEventKind::Finished {
                disposition,
                reason
            })
        );
    }
}

#[test]
fn terminal_only_incomplete_and_failed_after_partial_wrappers_are_accepted() {
    let terminal_only = event(
        0,
        json!({
            "type": "response.incomplete",
            "response": response(
                "incomplete",
                json!([completed_item("terminal partial", "incomplete")]),
                serde_json::Value::Null
            )
        }),
    );
    let events = decode(terminal_only.as_bytes()).expect("terminal-only incomplete");
    assert!(matches!(
        events.get(1).map(gocode_provider::ProviderStreamEvent::kind),
        Some(ProviderStreamEventKind::TextDelta { text }) if text == "terminal partial"
    ));

    let mut failed_after_partial = String::new();
    failed_after_partial.push_str(&event(
        0,
        json!({"type": "response.created", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    failed_after_partial.push_str(&event(
        1,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    failed_after_partial.push_str(&event(
        2,
        json!({"type": "response.output_item.added", "output_index": 0, "item": added_item()}),
    ));
    failed_after_partial.push_str(&event(
        3,
        json!({
            "type": "response.content_part.added",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": added_part()
        }),
    ));
    failed_after_partial.push_str(&event(
        4,
        json!({
            "type": "response.output_text.delta",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "delta": "partial before failure"
        }),
    ));
    failed_after_partial.push_str(&event(
        5,
        json!({
            "type": "response.failed",
            "response": response("failed", json!([]), serde_json::Value::Null)
        }),
    ));
    let events = decode(failed_after_partial.as_bytes()).expect("failed after partial");
    assert!(events.iter().any(|event| matches!(
        event.kind(),
        ProviderStreamEventKind::TextDelta { text } if text == "partial before failure"
    )));
}

#[test]
fn fragmented_crlf_comments_and_split_utf8_are_supported() {
    let original = String::from_utf8(successful_sse()).expect("UTF-8 fixture");
    let wire = format!(": heartbeat\r\n\r\n{}", original.replace('\n', "\r\n"));
    let mut decoder = OpenAiSseDecoder::default();
    for byte in wire.as_bytes() {
        decoder.push(&[*byte]).expect("fragment");
    }
    let events = decoder.finish().expect("fragmented stream");
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event.kind() {
                ProviderStreamEventKind::TextDelta { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>(),
        "Привет, world"
    );
}

#[test]
fn maximum_small_event_sequence_decodes_without_front_drain_amplification() {
    let delta_count = OPENAI_MAX_SSE_EVENTS - 8;
    let text = "x".repeat(delta_count);
    let mut wire = String::new();
    wire.push_str(&event(
        0,
        json!({"type": "response.created", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    wire.push_str(&event(
        1,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    wire.push_str(&event(
        2,
        json!({"type": "response.output_item.added", "output_index": 0, "item": added_item()}),
    ));
    wire.push_str(&event(
        3,
        json!({
            "type": "response.content_part.added",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": added_part()
        }),
    ));
    for sequence in 4..(4 + delta_count) {
        wire.push_str(&event(
            sequence as u64,
            json!({
                "type": "response.output_text.delta",
                "item_id": ITEM_ID,
                "output_index": 0,
                "content_index": 0,
                "delta": "x"
            }),
        ));
    }
    let mut sequence = (4 + delta_count) as u64;
    wire.push_str(&event(
        sequence,
        json!({
            "type": "response.output_text.done",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "text": text
        }),
    ));
    sequence += 1;
    wire.push_str(&event(
        sequence,
        json!({
            "type": "response.content_part.done",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": completed_part(&text)
        }),
    ));
    sequence += 1;
    wire.push_str(&event(
        sequence,
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": completed_item(&text, "completed")
        }),
    ));
    sequence += 1;
    wire.push_str(&event(
        sequence,
        json!({
            "type": "response.completed",
            "response": response(
                "completed",
                json!([completed_item(&text, "completed")]),
                json!({
                    "input_tokens": 1,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 1,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 2
                })
            )
        }),
    ));

    let events = decode(wire.as_bytes()).expect("maximum event sequence");
    assert_eq!(events.len(), delta_count + 3);
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event.kind() {
                ProviderStreamEventKind::TextDelta { text } => Some(text.len()),
                _ => None,
            })
            .sum::<usize>(),
        delta_count
    );
}

#[test]
fn identities_indexes_wrappers_and_remote_sequence_fail_closed() {
    let valid = String::from_utf8(successful_sse()).expect("fixture");
    let mutations = [
        valid.replacen(RESPONSE_ID, "resp_wrong", 1),
        valid.replacen(OPENAI_REQUEST_MODEL, "gpt-5.5", 1),
        valid.replacen(&format!("\"model\":\"{OPENAI_REQUEST_MODEL}\","), "", 1),
        valid.replacen(
            &format!("\"model\":\"{OPENAI_REQUEST_MODEL}\""),
            "\"model\":null",
            1,
        ),
        valid.replacen(OPENAI_SERVICE_TIER, "auto", 1),
        valid.replacen(OPENAI_SERVICE_TIER, "priority", 1),
        valid.replacen(OPENAI_SERVICE_TIER, "flex", 1),
        valid.replacen(
            &format!("\"service_tier\":\"{OPENAI_SERVICE_TIER}\""),
            "\"service_tier\":null",
            1,
        ),
        valid.replacen(
            &format!("\"service_tier\":\"{OPENAI_SERVICE_TIER}\","),
            "",
            1,
        ),
        valid.replacen(ITEM_ID, "msg_wrong", 1),
        valid.replacen("\"output_index\":0", "\"output_index\":1", 1),
        valid.replacen("\"content_index\":0", "\"content_index\":1", 1),
        valid.replacen("event: response.in_progress", "event: response.created", 1),
        valid.replacen(
            "event: response.output_item.added\ndata:",
            "event: response.output_text.delta\ndata:",
            1,
        ),
        valid.replacen("\"sequence_number\":5", "\"sequence_number\":4", 1),
    ];
    for mutation in mutations {
        assert!(decode(mutation.as_bytes()).is_err());
    }
}

#[test]
fn unsupported_events_output_and_annotations_fail_closed() {
    let unsupported = [
        event(
            0,
            json!({"type": "response.queued", "response": {"id": RESPONSE_ID, "status": "queued"}}),
        ),
        event(
            0,
            json!({"type": "response.reasoning_text.delta", "item_id": ITEM_ID, "output_index": 0, "content_index": 0, "delta": "hidden"}),
        ),
        event(
            0,
            json!({"type": "response.output_text.annotation.added", "item_id": ITEM_ID, "output_index": 0, "content_index": 0, "annotation_index": 0, "annotation": {}}),
        ),
        event(0, json!({"type": "response.future"})),
    ];
    for body in unsupported {
        assert!(decode(body.as_bytes()).is_err());
    }

    let annotated = String::from_utf8(successful_sse()).unwrap().replacen(
        "\"annotations\":[]",
        "\"annotations\":[{}]",
        1,
    );
    assert!(decode(annotated.as_bytes()).is_err());
    let second_output = String::from_utf8(successful_sse()).unwrap().replacen(
        "\"output_index\":0",
        "\"output_index\":1",
        1,
    );
    assert!(decode(second_output.as_bytes()).is_err());
}

#[test]
fn bounds_missing_usage_and_eof_without_terminal_fail_closed() {
    let oversized = format!(
        "event: error\ndata: {{\"type\":\"error\",\"code\":\"x\",\"message\":\"{}\",\"param\":null,\"sequence_number\":0}}\n\n",
        "x".repeat(65_536)
    );
    assert!(decode(oversized.as_bytes()).is_err());

    let missing_usage = String::from_utf8(successful_sse())
        .unwrap()
        .replace(
            "\"usage\":{\"input_tokens\":11,\"input_tokens_details\":{\"cached_tokens\":3},\"output_tokens\":4,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":15}",
            "\"usage\":null",
        );
    assert!(decode(missing_usage.as_bytes()).is_err());

    let truncated = String::from_utf8(successful_sse())
        .unwrap()
        .split("event: response.completed")
        .next()
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(decode(&truncated).is_err());
}

#[test]
fn dense_comment_lines_exceeding_parser_work_budget_fail_closed() {
    let mut decoder = OpenAiSseDecoder::default();
    let comments = ":\n\n".repeat((OPENAI_MAX_SSE_LINES / 2) + 1);
    assert_eq!(
        decoder.push(comments.as_bytes()),
        Err(OpenAiStreamError::StreamLimitExceeded)
    );
}

#[test]
fn errors_are_redacted_from_secret_body_and_remote_diagnostics() {
    let secret = "fixture-credential-never-print";
    let body = format!(
        "event: error\ndata: {{\"type\":\"error\",\"code\":\"x\",\"message\":\"{secret}\",\"param\":null,\"sequence_number\":0,\"unexpected\":true}}\n\n"
    );
    let error = decode(body.as_bytes()).expect_err("invalid event");
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains(secret));
    assert!(!diagnostic.contains("unexpected"));
    assert!(!diagnostic.contains("event:"));
}
