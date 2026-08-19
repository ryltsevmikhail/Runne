use runne_provider::{ProviderFinishReason, ProviderStreamEventKind, ProviderTerminalDisposition};
use runne_provider_deepseek::{
    DEEPSEEK_MAX_SSE_EVENTS, DEEPSEEK_MAX_SSE_LINES, DEEPSEEK_REQUEST_MODEL, DEEPSEEK_SERVICE_TIER,
    DeepSeekSseDecoder, DeepSeekStreamError,
};
use serde_json::json;

use support::{
    ITEM_ID, RESPONSE_ID, added_item, added_part, completed_item, completed_part, event,
    failed_sse, incomplete_sse, response, standalone_error_sse, successful_sse,
};

fn decode(bytes: &[u8]) -> Result<Vec<runne_provider::ProviderStreamEvent>, DeepSeekStreamError> {
    let mut decoder = DeepSeekSseDecoder::default();
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
                .map(runne_provider::ProviderStreamEvent::kind),
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
                .map(runne_provider::ProviderStreamEvent::kind),
            Some(ProviderStreamEventKind::UsageUnavailable)
        ));
        assert_eq!(
            events
                .last()
                .map(runne_provider::ProviderStreamEvent::kind),
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
        events.get(1).map(runne_provider::ProviderStreamEvent::kind),
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
    let mut decoder = DeepSeekSseDecoder::default();
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
    let delta_count = DEEPSEEK_MAX_SSE_EVENTS - 8;
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
