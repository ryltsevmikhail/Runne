
#[test]
fn documented_stream_may_omit_the_in_progress_wrapper() {
    let null_usage = serde_json::Value::Null;
    let mut wire = String::new();
    wire.push_str(&event(
        0,
        json!({"type": "response.created", "response": response("in_progress", json!([]), null_usage)}),
    ));
    wire.push_str(&event(
        1,
        json!({"type": "response.output_item.added", "output_index": 0, "item": added_item()}),
    ));
    wire.push_str(&event(
        2,
        json!({
            "type": "response.content_part.added",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": added_part()
        }),
    ));
    wire.push_str(&event(
        3,
        json!({
            "type": "response.output_text.delta",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "delta": "no wrapper"
        }),
    ));
    wire.push_str(&event(
        4,
        json!({
            "type": "response.output_text.done",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "text": "no wrapper"
        }),
    ));
    wire.push_str(&event(
        5,
        json!({
            "type": "response.content_part.done",
            "item_id": ITEM_ID,
            "output_index": 0,
            "content_index": 0,
            "part": completed_part("no wrapper")
        }),
    ));
    wire.push_str(&event(
        6,
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": completed_item("no wrapper", "completed")
        }),
    ));
    wire.push_str(&event(
        7,
        json!({
            "type": "response.completed",
            "response": response(
                "completed",
                json!([completed_item("no wrapper", "completed")]),
                json!({
                    "input_tokens": 3,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 2,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 5
                })
            )
        }),
    ));

    let events = decode(wire.as_bytes()).expect("in_progress wrapper is optional");
    assert_eq!(events.len(), 4);

    let mut duplicated_wrapper = String::new();
    duplicated_wrapper.push_str(&event(
        0,
        json!({"type": "response.created", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    duplicated_wrapper.push_str(&event(
        1,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    duplicated_wrapper.push_str(&event(
        2,
        json!({"type": "response.in_progress", "response": response("in_progress", json!([]), serde_json::Value::Null)}),
    ));
    assert_eq!(
        decode(duplicated_wrapper.as_bytes()),
        Err(DeepSeekStreamError::IllegalTransition)
    );
}
