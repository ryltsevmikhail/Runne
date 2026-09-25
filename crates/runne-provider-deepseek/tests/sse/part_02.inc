
#[test]
fn identities_indexes_wrappers_and_remote_sequence_fail_closed() {
    let valid = String::from_utf8(successful_sse()).expect("fixture");
    let mutations = [
        valid.replacen(RESPONSE_ID, "resp_wrong", 1),
        valid.replacen(DEEPSEEK_REQUEST_MODEL, "deepseek-v4-pro", 1),
        valid.replacen(&format!("\"model\":\"{DEEPSEEK_REQUEST_MODEL}\","), "", 1),
        valid.replacen(
            &format!("\"model\":\"{DEEPSEEK_REQUEST_MODEL}\""),
            "\"model\":null",
            1,
        ),
        valid.replacen(
            &format!("\"model\":\"{DEEPSEEK_REQUEST_MODEL}\""),
            "\"model\":\"deepseek-chat\"",
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
fn stored_provider_response_is_rejected() {
    let stored = String::from_utf8(successful_sse()).unwrap().replacen(
        "\"object\":\"response\"",
        "\"object\":\"response\",\"store\":true",
        1,
    );
    assert!(decode(stored.as_bytes()).is_err());
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
    let mut decoder = DeepSeekSseDecoder::default();
    let comments = ":\n\n".repeat((DEEPSEEK_MAX_SSE_LINES / 2) + 1);
    assert_eq!(
        decoder.push(comments.as_bytes()),
        Err(DeepSeekStreamError::StreamLimitExceeded)
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
