use super::*;
use crate::{ResponsesProfile, ResponsesProvider};
fn fixture(model: &str, id: &str) -> Vec<u8> {
    format!("event: response.created\ndata: {{\"sequence_number\":0,\"response\":{{\"id\":\"{id}\",\"model\":\"{model}\"}}}}\n\nevent: response.output_text.delta\ndata: {{\"sequence_number\":1,\"delta\":\"hi 😀\"}}\n\nevent: response.completed\ndata: {{\"sequence_number\":2,\"response\":{{\"id\":\"{id}\",\"model\":\"{model}\",\"usage\":{{\"input_tokens\":4,\"output_tokens\":3,\"input_tokens_details\":{{\"cached_tokens\":1}},\"output_tokens_details\":{{\"reasoning_tokens\":0}}}}}}}}\n\n").into_bytes()
}
#[test]
fn accepts_byte_fragmentation_and_usage() {
    let p = ResponsesProfile::new(ResponsesProvider::OpenAiCodex, "gpt-5.2");
    let mut d = ResponsesStreamDecoder::for_profile(&p);
    for byte in fixture("gpt-5.2", "resp_1") {
        d.push(&[byte]).unwrap();
    }
    let events = d.finish().unwrap();
    assert!(events.iter().any(
        |e| matches!(e.kind(), ProviderStreamEventKind::TextDelta { text } if text == "hi 😀")
    ));
    assert!(events.iter().any(|e| matches!(e.kind(), ProviderStreamEventKind::Usage { usage } if usage.input_tokens() == 4)));
}
#[test]
fn rejects_mixed_model_and_id() {
    let p = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4");
    let mut d = ResponsesStreamDecoder::for_profile(&p);
    let mut bytes = fixture("grok-4", "a");
    bytes.extend_from_slice(b"event: response.output_text.delta\ndata: {\"sequence_number\":3,\"response\":{\"id\":\"b\",\"model\":\"grok-4\"},\"delta\":\"late\"}\n\n");
    assert!(d.push(&bytes).is_err());
}
#[test]
fn rejects_unexpected_model_and_data_after_terminal() {
    let p = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4");
    let mut d = ResponsesStreamDecoder::for_profile(&p);
    let mut bytes = fixture("grok-3", "a");
    bytes.extend_from_slice(
        b"event: response.output_text.delta\ndata: {\"sequence_number\":3,\"delta\":\"late\"}\n\n",
    );
    assert!(d.push(&bytes).is_err());
}

#[test]
fn rejects_present_non_numeric_usage_detail() {
    let p = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4");
    let mut d = ResponsesStreamDecoder::for_profile(&p);
    let bytes = fixture("grok-4", "a").into_iter().collect::<Vec<_>>();
    let malformed = String::from_utf8(bytes)
        .unwrap()
        .replace("\"cached_tokens\":1", "\"cached_tokens\":\"one\"");
    assert!(d.push(malformed.as_bytes()).is_err());
}
