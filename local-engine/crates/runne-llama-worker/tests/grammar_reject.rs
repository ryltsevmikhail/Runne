//! Grammar rejection and final-output validation (Plan Task 19
//! Step 2): compilation failure is a typed reject with zero effect;
//! invalid final output is rejected — partial output is never
//! accepted and no `finish` is produced for it.

use runne_llama_worker::grammar::{GrammarError, compile};
use runne_llama_worker::json_validate::{OutputRejected, validate_output};
use serde_json::json;

#[test]
fn unsupported_schema_fails_typed_with_zero_effect() {
    // Recursion-bearing: the compiler refuses; nothing else happens.
    let mut node = json!({"type": "string"});
    for _ in 0..24 {
        node = json!({"type": "object", "properties": {"inner": node}, "required": ["inner"], "additionalProperties": false});
    }
    assert_eq!(
        compile(&node).expect_err("depth"),
        GrammarError::CompilationFailed
    );
    // Optional properties are out of the compiled subset.
    let optional = json!({
        "type": "object",
        "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
        "required": ["a"]
    });
    assert_eq!(
        compile(&optional).expect_err("optional props"),
        GrammarError::CompilationFailed
    );
    // Open objects (no additionalProperties:false enforcement) also
    // refuse: the compiled subset is closed-object only.
    let open = json!({"type": "object", "properties": {"a": {"type": "string"}}});
    assert!(compile(&open).is_err());
}

#[test]
fn valid_output_passes_final_validation() {
    let schema = json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "tags": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["name", "age"]
    });
    let output = r#"{"name":"ada","age":36,"tags":["x"]}"#;
    assert!(validate_output(&schema, output).is_ok());
    // Whitespace-free or pretty: both parse the same.
    let pretty = "{\n  \"name\": \"ada\",\n  \"age\": 36\n}";
    assert!(validate_output(&schema, pretty).is_ok());
}

#[test]
fn invalid_output_rejects() {
    let schema = json!({
        "type": "object",
        "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
        "required": ["name", "age"]
    });
    // Missing required key.
    assert_eq!(
        validate_output(&schema, r#"{"name":"ada"}"#),
        Err(OutputRejected)
    );
    // Wrong type.
    assert_eq!(
        validate_output(&schema, r#"{"name":1,"age":2}"#),
        Err(OutputRejected)
    );
    // Additional key in a closed subset.
    let closed = json!({
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
        "additionalProperties": false
    });
    assert_eq!(
        validate_output(&closed, r#"{"name":"ada","extra":1}"#),
        Err(OutputRejected)
    );
    // Not JSON at all / truncated (partial output).
    assert_eq!(validate_output(&schema, "not json"), Err(OutputRejected));
    assert_eq!(
        validate_output(&schema, r#"{"name":"ad"#),
        Err(OutputRejected)
    );
}
