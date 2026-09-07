//! Structured-output subset (Plan Task 19 Step 1): out-of-subset
//! keywords, bounds violations and malformed requests reject typed;
//! a valid subset request compiles and its digest feeds identity.

mod common;

use common::{AllowPermit, SettlementPort, adapter, admit_model, call};
use runne_provider_local::port::ProviderPort;
use runne_provider_local::structured::{StructuredError, StructuredMode, StructuredRequest};
use runne_provider_local::structured_schema::{SchemaError, validate_schema_subset};
use serde_json::{Value, json};

const NAMESPACE: &str = "local-engine.structured-output.v1";

fn schema_object() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "tags": {"type": "array", "items": {"type": "string"}},
            "active": {"type": "boolean"},
            "kind": {"enum": ["a", "b"]}
        },
        "required": ["name", "age"],
        "additionalProperties": false
    })
}

#[test]
fn valid_subset_compiles() {
    let ext = json!({NAMESPACE: {"mode": "schema-json", "schema": schema_object()}});
    let req = StructuredRequest::from_extension(&ext).expect("valid subset");
    let req = req.expect("some");
    assert_eq!(req.mode, StructuredMode::SchemaJson);
    assert!(req.schema_digest.starts_with("sha256:"));
    assert!(
        req.canonical_schema
            .expect("canonical")
            .contains("\"name\"")
    );
}

#[test]
fn out_of_subset_keywords_reject() {
    for keyword in [
        "$ref",
        "definitions",
        "oneOf",
        "anyOf",
        "allOf",
        "not",
        "if",
        "patternProperties",
    ] {
        let mut schema = schema_object();
        schema[keyword] = json!({"x": 1});
        let ext = json!({NAMESPACE: {"mode": "schema-json", "schema": schema}});
        match StructuredRequest::from_extension(&ext).expect_err(keyword) {
            StructuredError::Schema(SchemaError::UnsupportedKeyword(k)) => {
                assert_eq!(k, keyword);
            }
            other => panic!("expected unsupported keyword {keyword}, got {other:?}"),
        }
    }
}

#[test]
fn deep_recursion_rejects_by_depth() {
    // A nesting chain deeper than the depth bound.
    let mut node = json!({"type": "string"});
    for _ in 0..24 {
        node = json!({"type": "object", "properties": {"inner": node}, "required": ["inner"], "additionalProperties": false});
    }
    let err =
        validate_schema_subset(&serde_json_canonicalizer::to_string(&node).expect("canonical"))
            .expect_err("depth");
    assert_eq!(err, SchemaError::TooDeep);
}

#[test]
fn oversize_schema_rejects() {
    let mut schema = schema_object();
    schema["description"] = Value::String("z".repeat(13 * 1024));
    let canonical = serde_json_canonicalizer::to_string(&schema).expect("canonical");
    let err = validate_schema_subset(&canonical).expect_err("size");
    assert_eq!(err, SchemaError::TooLarge);
}

#[test]
fn unknown_mode_and_missing_schema_reject() {
    let ext = json!({NAMESPACE: {"mode": "yaml"}});
    assert_eq!(
        StructuredRequest::from_extension(&ext).expect_err("mode"),
        StructuredError::UnknownMode("yaml".into())
    );
    let ext = json!({NAMESPACE: {"mode": "schema-json"}});
    assert_eq!(
        StructuredRequest::from_extension(&ext).expect_err("schema"),
        StructuredError::SchemaRequired
    );
}

#[test]
fn plain_json_has_no_schema() {
    let ext = json!({NAMESPACE: {"mode": "plain-json"}});
    let req = StructuredRequest::from_extension(&ext)
        .expect("plain")
        .expect("some");
    assert_eq!(req.mode, StructuredMode::PlainJson);
    assert_eq!(req.schema_digest, "");

    let ext = json!({NAMESPACE: {"mode": "plain-json", "schema": schema_object()}});
    assert!(matches!(
        StructuredRequest::from_extension(&ext).expect_err("schema in plain"),
        StructuredError::Malformed
    ));
}

#[test]
fn schema_digest_feeds_attempt_identity() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let mut c = call(&fixture.manifest_digest, "hello");
    c.extension = json!({NAMESPACE: {"mode": "schema-json", "schema": schema_object()}});
    let p1 = a.prepare(&c).expect("prepare 1");
    let p2 = a.prepare(&c).expect("prepare 2");
    assert_eq!(p1.render_digest, p2.render_digest, "replay stable");
    assert!(p1.structured.is_some());
    let plain = call(&fixture.manifest_digest, "hello");
    let plain_prepared = a.prepare(&plain).expect("plain");
    assert_ne!(
        p1.render_digest, plain_prepared.render_digest,
        "structured attempt differs from unstructured"
    );
}
