#[test]
fn documented_monotonic_sequences_allow_gaps_without_requiring_zero_start() {
    let mut wire = String::new();
    wire.push_str(&event(
        41,
        json!({"type": "response.created", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    wire.push_str(&event(
        45,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    wire.push_str(&event(
        50,
        json!({"type": "response.output_item.added", "output_index": 0, "item": added_item()}),
    ));
    wire.push_str(&event(
        52,
        json!({
            "type": "response.content_part.added",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": added_part()
        }),
    ));
    wire.push_str(&event(
        57,
        json!({
            "type": "response.output_text.delta",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "delta": "gapped "
        }),
    ));
    wire.push_str(&event(
        60,
        json!({
            "type": "response.output_text.delta",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "delta": "wire"
        }),
    ));
    wire.push_str(&event(
        63,
        json!({
            "type": "response.output_text.done",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "text": "gapped wire"
        }),
    ));
    wire.push_str(&event(
        70,
        json!({
            "type": "response.content_part.done",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": completed_part("gapped wire")
        }),
    ));
    wire.push_str(&event(
        77,
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": completed_item("gapped wire", "completed")
        }),
    ));
    wire.push_str(&event(
        90,
        json!({
            "type": "response.completed",
            "response": response(
                "completed",
                json!([completed_item("gapped wire", "completed")]),
                json!({
                    "input_tokens": 9,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 2,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 11
                })
            )
        }),
    ));

    let events = decode(wire.as_bytes()).expect("gapped monotonic stream is documented");
    assert_eq!(events.len(), 5);
}

#[test]
fn duplicate_and_reversed_remote_sequence_numbers_are_rejected() {
    let mut duplicate = String::new();
    duplicate.push_str(&event(
        3,
        json!({"type": "response.created", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    duplicate.push_str(&event(
        3,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    assert_eq!(
        decode(duplicate.as_bytes()),
        Err(DeepSeekStreamError::CorrelationMismatch)
    );

    let mut reversed = String::new();
    reversed.push_str(&event(
        7,
        json!({"type": "response.created", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    reversed.push_str(&event(
        6,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    assert_eq!(
        decode(reversed.as_bytes()),
        Err(DeepSeekStreamError::CorrelationMismatch)
    );
}

#[test]
fn completed_terminal_requires_exactly_consistent_usage_evidence() {
    let valid = String::from_utf8(successful_sse()).expect("fixture");
    let without_usage = valid.replacen(
        "\"usage\":{\"input_tokens\":11,\"input_tokens_details\":{\"cached_tokens\":3},\"output_tokens\":4,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":15}",
        "\"usage\":null",
        1,
    );
    assert_eq!(
        decode(without_usage.as_bytes()),
        Err(DeepSeekStreamError::InvalidUsage)
    );

    let inconsistent_total = valid.replacen("\"total_tokens\":15", "\"total_tokens\":14", 1);
    assert_eq!(
        decode(inconsistent_total.as_bytes()),
        Err(DeepSeekStreamError::InvalidUsage)
    );
}

#[test]
fn failed_and_incomplete_terminal_usage_is_optional_but_validated_when_present() {
    let mut failed_with_usage = String::new();
    failed_with_usage.push_str(&event(
        0,
        json!({"type": "response.created", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    failed_with_usage.push_str(&event(
        1,
        json!({
            "type": "response.failed",
            "response": response(
                "failed",
                json!([]),
                json!({
                    "input_tokens": 5,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 1,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 6
                })
            )
        }),
    ));
    let events = decode(failed_with_usage.as_bytes()).expect("failed with usage");
    assert_eq!(events.len(), 3);
    assert!(matches!(
        events[1].kind(),
        ProviderStreamEventKind::Usage { .. }
    ));

    let mut incomplete_with_usage = String::new();
    incomplete_with_usage.push_str(&event(
        0,
        json!({"type": "response.created", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    incomplete_with_usage.push_str(&event(
        1,
        json!({
            "type": "response.incomplete",
            "response": response(
                "incomplete",
                json!([completed_item("partial", "incomplete")]),
                json!({
                    "input_tokens": 5,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 1,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 6
                })
            )
        }),
    ));
    let events = decode(incomplete_with_usage.as_bytes()).expect("incomplete with usage");
    assert!(matches!(
        events[events.len() - 2].kind(),
        ProviderStreamEventKind::Usage { .. }
    ));
    assert_eq!(
        events.last().map(runne_provider::ProviderStreamEvent::kind),
        Some(&ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteIncomplete,
            reason: ProviderFinishReason::Length
        })
    );
}

#[test]
fn incomplete_content_filter_reason_maps_to_content_filter_finish() {
    let body = event(
        0,
        json!({
            "type": "response.incomplete",
            "response": {
                "id": RESPONSE_ID,
                "model": runne_provider_deepseek::DEEPSEEK_REQUEST_MODEL,
                "object": "response",
                "status": "incomplete",
                "output": json!([]),
                "usage": serde_json::Value::Null,
                "error": serde_json::Value::Null,
                "incomplete_details": {"reason": "content_filter"}
            }
        }),
    );
    let events = decode(body.as_bytes()).expect("content filter incomplete");
    assert_eq!(
        events.last().map(runne_provider::ProviderStreamEvent::kind),
        Some(&ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteIncomplete,
            reason: ProviderFinishReason::ContentFilter
        })
    );
}
