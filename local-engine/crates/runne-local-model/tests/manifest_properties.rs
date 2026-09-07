//! Property/negative tests: RFC 8785 number bounds, duplicate keys,
//! unknown/nested members, canonical-form requirement, digest preimage
//! rules (top-level omission only), stability of parse→omit→JCS→hash.

use runne_local_model::{ManifestError, ModelManifestV1, canonicalize_strict, compute_digest};

const GOLDEN_JSON: &str = include_str!("../../../docs/golden/local-engine/model-manifest-v1.json");

fn reject_variant(bytes: &[u8], variant: &str) {
    match ModelManifestV1::parse_and_verify(bytes) {
        Err(err) => assert!(
            format!("{err:?}").contains(variant) || format!("{err}").contains(variant),
            "expected {variant}, got {err:?}"
        ),
        Ok(_) => panic!("expected rejection ({variant})"),
    }
}

#[test]
fn non_canonical_input_is_rejected() {
    // Same content, non-canonical bytes (extra space) → NonCanonical.
    // (serde_json Value is a sorted map: any same-content re-serialization
    // is already canonical, so only byte-level differences can be tested.)
    let mutated = GOLDEN_JSON.replacen("{", "{ ", 1);
    assert_ne!(mutated.as_bytes(), GOLDEN_JSON.trim_end().as_bytes());
    reject_variant(mutated.as_bytes(), "NonCanonical");
}

#[test]
fn duplicate_key_is_rejected() {
    let bytes = GOLDEN_JSON.trim_end().as_bytes().to_vec();
    // Inject a duplicated top-level key by textual splice: replace
    // `"format":"GGUF",` with `"format":"GGUF","format":"GGUF",`
    let pattern = b"\"format\":\"GGUF\",";
    let pos = bytes
        .windows(pattern.len())
        .position(|w| w == pattern)
        .expect("pattern present");
    let dup: Vec<u8> = bytes[..pos + pattern.len()]
        .iter()
        .copied()
        .chain(pattern.iter().copied())
        .chain(bytes[pos + pattern.len()..].iter().copied())
        .collect();
    reject_variant(&dup, "Duplicate");
}

#[test]
fn unknown_top_level_member_is_rejected() {
    // Injected at its sorted position (artifacts < bogusMember <
    // capabilities) so canonical-form equality passes and the SCHEMA gate
    // is the one that rejects.
    let pattern = "],\"capabilities\":";
    let injected = GOLDEN_JSON.replacen(pattern, "],\"bogusMember\":1,\"capabilities\":", 1);
    assert_ne!(injected, GOLDEN_JSON);
    reject_variant(injected.as_bytes(), "Schema");
}

#[test]
fn nested_manifest_digest_member_is_rejected() {
    // A nested same-named member is an unknown field for its object —
    // schema must reject; only the top-level member has special meaning.
    // Injected inside capabilities at its sorted position.
    let pattern = "\"modalities\":[\"text\"]";
    let injected = GOLDEN_JSON.replacen(
        pattern,
        &format!("\"manifestDigest\":\"sha256:{}\",{pattern}", "a".repeat(64)),
        1,
    );
    assert_ne!(injected, GOLDEN_JSON);
    reject_variant(injected.as_bytes(), "Schema");
}

#[test]
fn float_number_is_rejected() {
    let mutated = GOLDEN_JSON.replacen("\"byteLength\":2415919104", "\"byteLength\":24.5", 1);
    reject_variant(mutated.as_bytes(), "Number");
}

#[test]
fn oversized_integer_is_rejected() {
    let mutated = GOLDEN_JSON.replacen(
        "\"byteLength\":2415919104",
        "\"byteLength\":9007199254740992",
        1,
    );
    reject_variant(mutated.as_bytes(), "Number");
}

#[test]
fn negative_integer_is_rejected() {
    let mutated = GOLDEN_JSON.replacen("\"byteLength\":2415919104", "\"byteLength\":-1", 1);
    reject_variant(mutated.as_bytes(), "Number");
}

#[test]
fn malformed_declared_digest_is_rejected() {
    let mutated = GOLDEN_JSON.replacen(
        "\"manifestDigest\":\"sha256:",
        "\"manifestDigest\":\"sha3-256:",
        1,
    );
    reject_variant(mutated.as_bytes(), "Digest");
}

#[test]
fn declared_digest_mismatch_is_rejected() {
    // Replace exactly the declared digest value (key+value-quote aware).
    let key = "\"manifestDigest\":\"";
    let start = GOLDEN_JSON.find(key).expect("member present") + key.len();
    let end = start + "sha256:".len() + 64;
    let fake = format!("sha256:{}", "a".repeat(64));
    let mutated = format!("{}{}{}", &GOLDEN_JSON[..start], fake, &GOLDEN_JSON[end..]);
    assert_ne!(mutated, GOLDEN_JSON);
    reject_variant(mutated.as_bytes(), "Digest");
}

#[test]
fn digest_omits_only_top_level_member_and_is_stable() {
    // parse → omit (only top-level) → JCS → hash must equal the declared
    // digest; the fixture itself proves the omission because a digest over
    // the self-referential object is impossible.
    let verified = ModelManifestV1::parse_and_verify(GOLDEN_JSON.as_bytes()).unwrap();
    let value = canonicalize_strict(GOLDEN_JSON.as_bytes()).unwrap();
    assert_eq!(
        compute_digest(&value.value).unwrap().as_str(),
        verified.digest().as_str()
    );

    // Stability: digest of the preimage is independent of the declared
    // member value (replacing declared digest with another valid one fails
    // verification — covered above — and compute_digest never sees it).
    assert!(verified.digest().as_str().starts_with("sha256:"));
}

#[test]
fn changing_identity_member_changes_digest() {
    let value = canonicalize_strict(GOLDEN_JSON.as_bytes()).unwrap();
    let base = compute_digest(&value.value).unwrap();
    let mut v2 = value.value.clone();
    v2["modelID"] = serde_json::Value::String("other-model".into());
    let changed = compute_digest(&v2).unwrap();
    assert_ne!(base.as_str(), changed.as_str());
}

#[test]
fn canonicalize_strict_rejects_invalid_utf8() {
    let mut bytes = GOLDEN_JSON.trim_end().as_bytes().to_vec();
    bytes[10] = 0xFF;
    assert!(matches!(
        canonicalize_strict(&bytes),
        Err(ManifestError::InvalidUtf8)
    ));
}

#[test]
fn duplicate_modality_is_rejected() {
    let pattern = "\"modalities\":[\"text\"]";
    let injected = GOLDEN_JSON.replacen(pattern, "\"modalities\":[\"text\",\"text\"]", 1);
    assert_ne!(injected, GOLDEN_JSON);
    reject_variant(injected.as_bytes(), "Schema");
}
