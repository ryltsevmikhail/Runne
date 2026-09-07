//! Worker stream usage payload codec.

/// Usage items are CBOR-encoded `["u", prompt, output]` inside the
/// payload; the host parses them back strictly.
pub(crate) fn usage_payload(prompt_tokens: u64, output_tokens: u64) -> Vec<u8> {
    let mut out = Vec::new();
    runne_inference_protocol::cbor::encode(
        &runne_inference_protocol::Cbor::Array(vec![
            runne_inference_protocol::Cbor::Text("u".into()),
            runne_inference_protocol::Cbor::Unsigned(prompt_tokens),
            runne_inference_protocol::Cbor::Unsigned(output_tokens),
        ]),
        &mut out,
    );
    out
}

/// Inverse of [`usage_payload`]; rejects anything else.
pub fn parse_usage_payload(payload: &[u8]) -> Option<(u64, u64)> {
    let value = runne_inference_protocol::cbor::decode(payload).ok()?;
    let runne_inference_protocol::Cbor::Array(items) = value else {
        return None;
    };
    if items.len() != 3 {
        return None;
    }
    let runne_inference_protocol::Cbor::Text(tag) = &items[0] else {
        return None;
    };
    if tag != "u" {
        return None;
    }
    let runne_inference_protocol::Cbor::Unsigned(p) = items[1] else {
        return None;
    };
    let runne_inference_protocol::Cbor::Unsigned(o) = items[2] else {
        return None;
    };
    Some((p, o))
}
