//! Golden tests: canonical fixture parses, digest matches frozen vector,
//! and the implementation agrees with the cross-language (python JCS)
//! fixture generation.

use runne_local_model::{ModelManifestV1, canonicalize_strict, compute_digest};

const GOLDEN_JSON: &str = include_str!("../../../docs/golden/local-engine/model-manifest-v1.json");
const GOLDEN_SHA: &str = include_str!("../../../docs/golden/local-engine/model-manifest-v1.sha256");

#[test]
fn golden_parses_and_digest_matches() {
    let verified = ModelManifestV1::parse_and_verify(GOLDEN_JSON.as_bytes())
        .expect("golden fixture must parse");
    let expected = GOLDEN_SHA.trim();
    assert_eq!(verified.digest().as_str(), expected);
    assert_eq!(
        verified.manifest_id(),
        format!("local:qwen3-4b-instruct:r2026-08-01:{expected}")
    );
    assert_eq!(verified.model_id(), "qwen3-4b-instruct");
    assert_eq!(verified.artifacts().len(), 1);
    assert_eq!(verified.capabilities().context_max_tokens(), 8192);
}

#[test]
fn golden_is_canonical_and_recomputes_same_digest() {
    let value = canonicalize_strict(GOLDEN_JSON.as_bytes()).expect("canonical");
    assert_eq!(
        value.canonical,
        GOLDEN_JSON.trim_end(),
        "fixture frozen in canonical form"
    );
    let recomputed = compute_digest(&value.value).expect("digest");
    assert_eq!(recomputed.as_str(), GOLDEN_SHA.trim());
}

#[test]
fn one_byte_mutation_changes_digest_or_rejects() {
    // Mutate a digit inside the canonical body (still valid JSON) —
    // identity must move.
    let mutated = GOLDEN_JSON.replacen("\"byteLength\":2415919104", "\"byteLength\":2415919105", 1);
    assert_ne!(mutated, GOLDEN_JSON.trim_end());
    let value = canonicalize_strict(mutated.as_bytes()).expect("still canonical JSON");
    let recomputed = compute_digest(&value.value).expect("digest");
    assert_ne!(recomputed.as_str(), GOLDEN_SHA.trim());
}
