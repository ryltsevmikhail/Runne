use runne_provider::ProviderStreamEventKind;
use runne_provider_openai::{OPENAI_REQUEST_MODEL, OPENAI_SERVICE_TIER, OpenAiSseDecoder};
use serde_json::{Value, json};

fn frame(sequence: u64, event_type: &str, response: &Value) -> Vec<u8> {
    format!(
        "event: {event_type}\ndata: {}\n\n",
        json!({"type":event_type,"sequence_number":sequence,"response":response})
    )
    .into_bytes()
}

fn response() -> Value {
    json!({"id":"resp_early_1","object":"response","model":OPENAI_REQUEST_MODEL,
        "service_tier":OPENAI_SERVICE_TIER,"background":true,"store":false,
        "status":"in_progress","output":[],"usage":null})
}

#[test]
fn background_decoder_exposes_created_identity_before_parsing_buffered_next_frame() {
    let mut wire = frame(0, "response.created", &response());
    wire.extend(frame(1, "response.in_progress", &response()));
    let mut decoder = OpenAiSseDecoder::background();
    decoder.append_background_fragment(&wire).unwrap();

    assert!(decoder.process_background_frame().unwrap());
    assert_eq!(decoder.background_response_id(), Some("resp_early_1"));
    let first = decoder.take_background_events();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].sequence(), 0);
    assert!(matches!(first[0].kind(), ProviderStreamEventKind::Started));

    assert!(decoder.process_background_frame().unwrap());
    assert!(decoder.take_background_events().is_empty());
}

#[test]
fn draining_created_frame_does_not_duplicate_started_before_early_failure() {
    let mut failed = response();
    failed["status"] = json!("failed");
    failed["error"] = json!({"code":"server_error","message":"failed"});
    let mut wire = frame(0, "response.created", &response());
    wire.extend(frame(1, "response.failed", &failed));
    let mut decoder = OpenAiSseDecoder::background();
    decoder.append_background_fragment(&wire).unwrap();

    assert!(decoder.process_background_frame().unwrap());
    let created = decoder.take_background_events();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].sequence(), 0);
    assert!(matches!(
        created[0].kind(),
        ProviderStreamEventKind::Started
    ));
    assert!(decoder.process_background_frame().unwrap());
    let terminal = decoder.take_background_events();
    assert_eq!(terminal.len(), 2);
    assert_eq!(terminal[0].sequence(), 1);
    assert!(matches!(
        terminal[0].kind(),
        ProviderStreamEventKind::UsageUnavailable
    ));
    assert_eq!(terminal[1].sequence(), 2);
}

#[test]
fn background_decoder_rejects_non_background_created_response() {
    let mut response = response();
    response["background"] = json!(false);
    let mut decoder = OpenAiSseDecoder::background();
    decoder
        .append_background_fragment(&frame(0, "response.created", &response))
        .unwrap();
    assert!(decoder.process_background_frame().is_err());
}

#[test]
fn queued_created_response_transitions_to_progress_and_terminal() {
    let mut queued = response();
    queued["status"] = json!("queued");
    let mut wire = frame(0, "response.created", &queued);
    wire.extend(frame(1, "response.queued", &queued));
    wire.extend(frame(2, "response.in_progress", &response()));
    let mut failed = response();
    failed["status"] = json!("failed");
    failed["error"] = json!({"code":"server_error","message":"safe"});
    wire.extend(frame(3, "response.failed", &failed));
    let mut decoder = OpenAiSseDecoder::background();
    decoder.append_background_fragment(&wire).unwrap();

    assert!(decoder.process_background_frame().unwrap());
    assert_eq!(decoder.background_response_id(), Some("resp_early_1"));
    let created = decoder.take_background_events();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].sequence(), 0);
    assert!(matches!(
        created[0].kind(),
        ProviderStreamEventKind::Started
    ));
    assert!(decoder.process_background_frame().unwrap());
    assert!(decoder.take_background_events().is_empty());
    assert!(decoder.process_background_frame().unwrap());
    assert!(decoder.take_background_events().is_empty());
    assert!(decoder.process_background_frame().unwrap());
    let terminal = decoder.take_background_events();
    assert_eq!(terminal.len(), 2);
    assert_eq!(terminal[0].sequence(), 1);
    assert!(matches!(
        terminal[0].kind(),
        ProviderStreamEventKind::UsageUnavailable
    ));
    assert_eq!(terminal[1].sequence(), 2);
    assert!(matches!(
        terminal[1].kind(),
        ProviderStreamEventKind::Finished { .. }
    ));
}

#[test]
fn queued_event_requires_exact_id_and_remote_sequence() {
    for (queued_id, queued_sequence) in [("resp_other", 1), ("resp_early_1", 2)] {
        let mut created = response();
        created["status"] = json!("queued");
        let mut queued = created.clone();
        queued["id"] = json!(queued_id);
        let mut decoder = OpenAiSseDecoder::background();
        decoder
            .append_background_fragment(&frame(0, "response.created", &created))
            .unwrap();
        assert!(decoder.process_background_frame().unwrap());
        decoder
            .append_background_fragment(&frame(queued_sequence, "response.queued", &queued))
            .unwrap();
        assert!(decoder.process_background_frame().is_err());
    }
}

#[test]
fn queued_event_is_rejected_after_nonqueued_created_response() {
    let in_progress = response();
    let mut decoder = OpenAiSseDecoder::background();
    decoder
        .append_background_fragment(&frame(0, "response.created", &in_progress))
        .unwrap();
    assert!(decoder.process_background_frame().unwrap());
    decoder
        .append_background_fragment(&frame(1, "response.queued", &in_progress))
        .unwrap();
    assert!(decoder.process_background_frame().is_err());
}

#[test]
fn queued_created_response_can_advance_directly_to_in_progress() {
    let mut created = response();
    created["status"] = json!("queued");
    let mut failed = response();
    failed["status"] = json!("failed");
    failed["error"] = json!({"code":"server_error","message":"safe"});
    let mut wire = frame(0, "response.created", &created);
    wire.extend(frame(1, "response.in_progress", &response()));
    wire.extend(frame(2, "response.failed", &failed));
    let mut decoder = OpenAiSseDecoder::background();
    decoder.append_background_fragment(&wire).unwrap();
    let mut events = Vec::new();
    while decoder.process_background_frame().unwrap() {
        events.extend(decoder.take_background_events());
    }
    assert_eq!(events.len(), 3);
    assert!(matches!(events[0].kind(), ProviderStreamEventKind::Started));
    assert_eq!(events[0].sequence(), 0);
    assert_eq!(events[1].sequence(), 1);
    assert_eq!(events[2].sequence(), 2);
}
