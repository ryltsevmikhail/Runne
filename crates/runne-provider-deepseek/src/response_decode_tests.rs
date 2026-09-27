use super::decode_transport_response_with_diagnostic;
use crate::{
    DeepSeekDecodeEventKind, DeepSeekDecodeIssue, DeepSeekStreamError, DeepSeekTransportResponse,
};

#[test]
fn reports_closed_nested_field_without_including_wire_values() {
    let marker = "private-body-marker";
    let created = format!(
        "event: response.created\ndata: {{\"type\":\"response.created\",\"sequence_number\":0,\"response\":{{\"id\":\"{marker}\",\"object\":\"response\",\"model\":\"deepseek-flash\",\"status\":\"in_progress\",\"output\":[]}}}}\n\n"
    );
    let added = format!(
        "event: response.output_item.added\ndata: {{\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":0,\"item\":{{\"id\":\"{marker}\",\"role\":\"assistant\",\"status\":\"in_progress\",\"type\":\"message\",\"private_unknown\":\"{marker}\"}}}}\n\n"
    );
    let response = DeepSeekTransportResponse::sse(vec![[created, added].concat().into_bytes()])
        .expect("bounded response");

    let (result, detail) = decode_transport_response_with_diagnostic(&response);
    assert_eq!(result, Err(DeepSeekStreamError::MalformedEvent));
    let detail = detail.expect("closed schema detail");
    assert_eq!(detail.event, DeepSeekDecodeEventKind::OutputItemAdded);
    assert_eq!(detail.issue, DeepSeekDecodeIssue::MissingField);
    assert_eq!(detail.ordinals(), (2, 2, 5, 17, 9));
    assert!(!format!("{detail:?}").contains(marker));
    assert!(!format!("{detail:?}").contains("private_unknown"));
}

#[test]
fn distinguishes_nested_message_phase_from_outer_response_id() {
    let header = "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"r\",\"object\":\"response\",\"model\":\"deepseek-flash\",\"status\":\"in_progress\",\"output\":[]}}\n\n";
    let nested = format!(
        "event: response.output_item.added\ndata: {{\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":0,\"item\":{{\"content\":[],\"id\":\"m\",\"role\":\"assistant\",\"status\":\"in_progress\",\"type\":\"message\",\"phase\":\"{marker}\"}}}}\n\n",
        marker = "private-phase-value"
    );
    let (result, detail) = decode_wire(format!("{header}{nested}"));
    assert_eq!(result, Err(DeepSeekStreamError::MalformedEvent));
    let detail = detail.expect("closed nested key detail");
    assert_eq!(detail.node as u8, 5);
    assert_eq!(detail.field as u8, 42);
    assert_eq!(detail.issue, DeepSeekDecodeIssue::ValueMismatch);
    assert!(!format!("{detail:?}").contains("private-phase-value"));

    let outer = "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":0,\"response_id\":\"private-response-id\",\"item\":{\"content\":[],\"id\":\"m\",\"role\":\"assistant\",\"status\":\"in_progress\",\"type\":\"message\"}}\n\n";
    let (result, detail) = decode_wire(format!("{header}{outer}"));
    assert_eq!(result, Err(DeepSeekStreamError::MalformedEvent));
    let detail = detail.expect("closed outer key detail");
    assert_eq!(detail.node as u8, 2);
    assert_eq!(detail.field as u8, 44);
    assert_eq!(detail.issue, DeepSeekDecodeIssue::UnexpectedField);
    assert!(!format!("{detail:?}").contains("private-response-id"));

    let outer_phase = outer.replace("response_id", "phase");
    let (result, detail) = decode_wire(format!("{header}{outer_phase}"));
    assert_eq!(result, Err(DeepSeekStreamError::MalformedEvent));
    let detail = detail.expect("outer phase remains rejected");
    assert_eq!(detail.node as u8, 2);
    assert_eq!(detail.field as u8, 42);
    assert_eq!(detail.issue, DeepSeekDecodeIssue::UnexpectedField);
}

fn decode_wire(
    wire: String,
) -> (
    Result<Vec<runne_provider::ProviderStreamEvent>, DeepSeekStreamError>,
    Option<crate::DeepSeekDecodeDiagnostic>,
) {
    let response =
        DeepSeekTransportResponse::sse(vec![wire.into_bytes()]).expect("bounded response");
    decode_transport_response_with_diagnostic(&response)
}

#[test]
fn successful_frame_does_not_leak_event_kind_into_next_line_error() {
    let wire = b"event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"r\",\"object\":\"response\",\"model\":\"deepseek-flash\",\"status\":\"in_progress\",\"output\":[]}}\n\nx-private-field: ignored\n";
    let response = DeepSeekTransportResponse::sse(vec![wire.to_vec()]).expect("bounded response");
    let (result, detail) = decode_transport_response_with_diagnostic(&response);
    assert_eq!(result, Err(DeepSeekStreamError::MalformedEvent));
    let detail = detail.expect("closed frame detail");
    assert_eq!(detail.event, DeepSeekDecodeEventKind::Unknown);
    assert_eq!(detail.issue, DeepSeekDecodeIssue::UnsupportedSseField);
}

#[test]
fn wrong_type_added_content_keeps_unknown_event_error() {
    let wire = concat!(
        "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"r\",\"object\":\"response\",\"model\":\"deepseek-flash\",\"status\":\"in_progress\",\"output\":[]}}\n\n",
        "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":0,\"item\":{\"id\":\"i\",\"role\":\"assistant\",\"status\":\"in_progress\",\"type\":\"message\",\"content\":\"wrong-type\"}}\n\n",
    );
    let response =
        DeepSeekTransportResponse::sse(vec![wire.as_bytes().to_vec()]).expect("bounded response");
    let (result, detail) = decode_transport_response_with_diagnostic(&response);
    assert_eq!(result, Err(DeepSeekStreamError::UnknownEvent));
    assert_eq!(
        detail.expect("closed field detail").issue,
        DeepSeekDecodeIssue::WrongType
    );
}

#[test]
fn wrong_type_annotations_keeps_unknown_event_error() {
    let wire = concat!(
        "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"r\",\"object\":\"response\",\"model\":\"deepseek-flash\",\"status\":\"in_progress\",\"output\":[]}}\n\n",
        "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":0,\"item\":{\"id\":\"i\",\"role\":\"assistant\",\"status\":\"in_progress\",\"type\":\"message\",\"content\":[]}}\n\n",
        "event: response.content_part.added\ndata: {\"type\":\"response.content_part.added\",\"sequence_number\":2,\"output_index\":0,\"content_index\":0,\"item_id\":\"i\",\"part\":{\"annotations\":\"wrong-type\",\"text\":\"\",\"type\":\"output_text\"}}\n\n",
    );
    let response =
        DeepSeekTransportResponse::sse(vec![wire.as_bytes().to_vec()]).expect("bounded response");
    let (result, detail) = decode_transport_response_with_diagnostic(&response);
    assert_eq!(result, Err(DeepSeekStreamError::UnknownEvent));
    let detail = detail.expect("closed field detail");
    assert_eq!(detail.field, crate::DeepSeekDecodeField::Annotations);
    assert_eq!(detail.issue, DeepSeekDecodeIssue::WrongType);
}

#[test]
fn wrong_type_terminal_annotations_keeps_unknown_event_error() {
    let wire = concat!(
        "event: response.failed\ndata: {\"type\":\"response.failed\",\"sequence_number\":0,\"response\":{\"id\":\"r\",\"object\":\"response\",\"model\":\"deepseek-flash\",\"status\":\"failed\",\"output\":[{\"id\":\"i\",\"role\":\"assistant\",\"status\":\"failed\",\"type\":\"message\",\"content\":[{\"annotations\":\"wrong-type\",\"text\":\"partial\",\"type\":\"output_text\"}]}],\"error\":{\"code\":\"failed\",\"message\":\"failed\"}}}\n\n",
    );
    let response =
        DeepSeekTransportResponse::sse(vec![wire.as_bytes().to_vec()]).expect("bounded response");
    let (result, detail) = decode_transport_response_with_diagnostic(&response);
    assert_eq!(result, Err(DeepSeekStreamError::UnknownEvent));
    let detail = detail.expect("closed field detail");
    assert_eq!(detail.event, DeepSeekDecodeEventKind::ResponseFailed);
    assert_eq!(detail.field, crate::DeepSeekDecodeField::Annotations);
    assert_eq!(detail.issue, DeepSeekDecodeIssue::WrongType);
}
