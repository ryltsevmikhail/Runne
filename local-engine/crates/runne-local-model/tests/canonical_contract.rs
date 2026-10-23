//! Shared old/new byte contract. RFC 8785 §§3.2.2–3.2.3 and Appendix B;
//! finite regression vectors, not a proof for all possible serialized values.
mod builder_common;

use runne_local_model::{ModelManifestV1, canonicalize_strict, compute_digest};
use serde::ser::SerializeMap;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn check(label: &str, value: &Value, expected: &str) {
    let bytes = serde_json_canonicalizer::to_vec(value).expect(label);
    assert_eq!(bytes, expected.as_bytes(), "{label}: exact JCS bytes");
    let hash = Sha256::digest(&bytes);
    assert_eq!(hash, Sha256::digest(expected.as_bytes()), "{label}: SHA256");
    println!(
        "VECTOR {label} bytes={} sha256={}",
        hex::encode(bytes),
        hex::encode(hash)
    );
}

#[test]
fn common_nested_and_string_escaping() {
    check(
        "nested",
        &json!({"z": [null, true, {"b": 2, "a": 1}], "a": []}),
        r#"{"a":[],"z":[null,true,{"a":1,"b":2}]}"#,
    );
    check(
        "escapes",
        &json!("\u{0}\u{8}\t\n\u{c}\r\"\\/é😀"),
        r#""\u0000\b\t\n\f\r\"\\/é😀""#,
    );
}

#[test]
fn common_utf16_key_order_not_utf8_or_scalar_order() {
    check(
        "utf16",
        &json!({"\u{fb33}":7,"😀":6,"€":5,"ö":4,"\u{80}":3,"1":2,"\r":1}),
        "{\"\\r\":1,\"1\":2,\"\u{80}\":3,\"ö\":4,\"€\":5,\"😀\":6,\"דּ\":7}",
    );
}

#[test]
fn common_rfc_number_boundaries_direct_domain() {
    // Direct canonicalizer/provider numeric domain is wider than V1 manifests,
    // whose strict parser permits only nonnegative safe integers.
    let cases = [
        ("minus-zero", -0.0, "0"),
        ("min-subnormal", f64::from_bits(1), "5e-324"),
        ("max-finite", f64::MAX, "1.7976931348623157e+308"),
        ("safe-integer", 9007199254740991.0, "9007199254740991"),
        ("fixed-boundary", 1e-6, "0.000001"),
        ("scientific-boundary", 1e-7, "1e-7"),
        ("large-fixed", 1e20, "100000000000000000000"),
        ("large-scientific", 1e21, "1e+21"),
        ("rfc-rounded", 333333333.3333333, "333333333.3333333"),
        ("rfc-exponent", 1e30, "1e+30"),
        ("rfc-decimal", 4.5, "4.5"),
        ("rfc-small", 0.002, "0.002"),
        ("rfc-tiny", 1e-27, "1e-27"),
    ];
    for (name, number, expected) in cases {
        check(name, &Value::from(number), expected);
    }
}

#[test]
fn common_strict_public_domain_and_raw_duplicate_refusal() {
    let canonical = r#"{"n":9007199254740991,"nested":{"manifestDigest":"retained"}}"#;
    let parsed = canonicalize_strict(canonical.as_bytes()).expect("safe integer domain");
    check("strict-public-domain", &parsed.value, canonical);
    assert!(canonicalize_strict(br#"{"a":1,"a":2}"#).is_err());
    assert!(canonicalize_strict(br#"{"a":1,"\u0061":2}"#).is_err());
    for invalid in ["-1", "1.5", "9007199254740992"] {
        assert!(canonicalize_strict(invalid.as_bytes()).is_err());
    }
}

#[test]
fn common_existing_manifest_and_builder_identity_bytes() {
    let golden = include_str!("../../../docs/golden/local-engine/model-manifest-v1.json");
    let digest = include_str!("../../../docs/golden/local-engine/model-manifest-v1.sha256").trim();
    let verified = ModelManifestV1::parse_and_verify(golden.as_bytes()).expect("golden");
    assert_eq!(verified.canonical(), golden.trim_end());
    assert_eq!(verified.digest().as_str(), digest);
    assert_eq!(
        verified.manifest_id(),
        format!("local:qwen3-4b-instruct:r2026-08-01:{digest}")
    );
    let value: Value = serde_json::from_str(golden).unwrap();
    check("manifest-golden", &value, golden.trim_end());
    assert_eq!(compute_digest(&value).unwrap().as_str(), digest);

    let built = runne_local_model::build_candidate_manifest(
        &mut std::io::Cursor::new(builder_common::gguf_with_metadata()),
        &builder_common::full_user(),
        runne_local_model::BUILDER_CONTRACT_VERSION,
    )
    .expect("synthetic zero-tensor fixture only");
    let frozen =
        include_str!("../../../docs/golden/local-engine/builder/golden-manifest.json").trim_end();
    assert_eq!(built.canonical_bytes, frozen.as_bytes());
    let value: Value = serde_json::from_str(frozen).unwrap();
    check("builder-golden", &value, frozen);
    assert_eq!(
        built.manifest_digest,
        compute_digest(&value).unwrap().as_str()
    );
    println!(
        "IDENTITY manifest={} builder={}",
        verified.manifest_id(),
        built.manifest_digest
    );
}

struct DuplicateMembers;
impl serde::Serialize for DuplicateMembers {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("same", &1_u32)?;
        map.serialize_entry("same", &2_u32)?;
        map.end()
    }
}

#[test]
fn intentional_custom_serialize_map_duplicate_rejection() {
    let result = serde_json_canonicalizer::to_vec(&DuplicateMembers);
    println!("DUPLICATE result={result:?}");
    let error = result.expect_err("duplicate SerializeMap keys must be rejected");
    assert!(error.to_string().contains("duplicate object key"));
}
