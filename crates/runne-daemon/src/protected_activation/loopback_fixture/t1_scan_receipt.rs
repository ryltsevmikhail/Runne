use std::path::Path;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct T1WireScanReceipt {
    request_byte_count: usize,
    request_sha256: String,
    request_canary_free: bool,
    response_byte_count: usize,
    response_sha256: String,
    response_canary_free: bool,
    response_sent: bool,
}

pub(super) fn write_t1_scan_receipt(
    path: &Path,
    request: &[u8],
    response: &[u8],
    response_sent: bool,
) -> Result<(), ()> {
    use sha2::{Digest as _, Sha256};
    let receipt = T1WireScanReceipt {
        request_byte_count: request.len(),
        request_sha256: hex::encode(Sha256::digest(request)),
        request_canary_free: t1_canary_free(request),
        response_byte_count: response.len(),
        response_sha256: hex::encode(Sha256::digest(response)),
        response_canary_free: t1_canary_free(response),
        response_sent,
    };
    let bytes = serde_json::to_vec(&receipt).map_err(|_| ())?;
    std::fs::write(path, bytes).map_err(|_| ())
}

fn t1_canary_free(bytes: &[u8]) -> bool {
    frozen_patterns().iter().all(|pattern| {
        representations(pattern)
            .iter()
            .all(|representation| !contains(bytes, representation))
    })
}

fn frozen_patterns() -> Vec<Vec<u8>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/golden/t1/fake-canary-secrets-v1.json"
    )))
    .expect("frozen T1 canary fixture");
    let content: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/golden/t1/project-content-canaries-v1.json"
    )))
    .expect("frozen project-content fixture");
    let secrets = fixture["canaries"]
        .as_array()
        .expect("frozen canaries")
        .iter()
        .filter_map(|canary| canary["value"].as_str());
    let project = content["canaries"]
        .as_array()
        .expect("frozen project canaries")
        .iter()
        .filter_map(|canary| canary["marker"].as_str());
    secrets
        .chain(project)
        .chain(std::iter::once("RUNNE_T1_FAKE"))
        .map(|pattern| pattern.as_bytes().to_vec())
        .collect()
}

fn representations(value: &[u8]) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(value);
    let unpadded = encoded.trim_end_matches('=').as_bytes().to_vec();
    vec![
        value.to_vec(),
        encoded.into_bytes(),
        unpadded,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(value)
            .into_bytes(),
        hex::encode(value).into_bytes(),
        hex::encode_upper(value).into_bytes(),
    ]
}

fn contains(bytes: &[u8], pattern: &[u8]) -> bool {
    !pattern.is_empty() && bytes.windows(pattern.len()).any(|window| window == pattern)
}

#[cfg(test)]
mod tests {
    use super::{frozen_patterns, t1_canary_free};
    use base64::Engine as _;

    #[test]
    fn frozen_wire_scanner_covers_independent_known_encodings() {
        let marker = frozen_patterns()
            .into_iter()
            .find(|pattern| pattern.starts_with(b"RUNNE_T1_FAKE_API_KEY_"))
            .expect("stable frozen synthetic canary");
        let standard = base64::engine::general_purpose::STANDARD.encode(&marker);
        let standard_unpadded = standard.trim_end_matches('=').to_owned();
        let url_unpadded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&marker);
        let lower_hex = hex::encode(&marker);
        let upper_hex = hex::encode_upper(&marker);
        let cases = [
            String::from_utf8(marker.clone()).expect("ASCII frozen marker"),
            standard,
            standard_unpadded,
            url_unpadded,
            lower_hex,
            upper_hex,
        ];
        for encoded in cases {
            assert!(
                !t1_canary_free(encoded.as_bytes()),
                "scanner must reject an independently constructed frozen representation"
            );
        }
        assert!(t1_canary_free(b"fixture-only clean bytes"));
    }
}
