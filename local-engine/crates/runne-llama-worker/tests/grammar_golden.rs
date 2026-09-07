//! Worker grammar golden (Plan Task 19 Step 2): valid subset schemas
//! compile deterministically to bounded GBNF handed to the backend
//! before generation starts.

use runne_llama_worker::grammar::compile;
use serde_json::json;

#[test]
fn object_schema_compiles_deterministically() {
    let schema = json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "active": {"type": "boolean"}
        },
        "required": ["name", "age", "active"],
        "additionalProperties": false
    });
    let g1 = compile(&schema).expect("compile");
    let g2 = compile(&schema).expect("compile");
    assert_eq!(g1.source, g2.source, "deterministic");
    assert_eq!(g1.digest, g2.digest);
    assert!(g1.source.starts_with("space ::= [ \\t]*\nroot ::= "));
    assert!(g1.source.contains("d"), "rule refs present");
}

#[test]
fn scalar_and_array_schemas_compile() {
    let cases = [
        json!({"type": "string"}),
        json!({"type": "integer"}),
        json!({"type": "number"}),
        json!({"type": "boolean"}),
        json!({"type": "null"}),
        json!({"type": "array", "items": {"type": "integer"}}),
        json!({"type": "object", "properties": {}, "required": []}),
    ];
    for schema in cases {
        compile(&schema).expect("compiles");
    }
}

#[test]
fn enum_schema_compiles_to_alternatives() {
    let schema = json!({"enum": ["a", "b"]});
    let g = compile(&schema).expect("compile");
    assert!(g.source.contains("\"a\""), "literal a");
    assert!(g.source.contains("\"b\""), "literal b");
    assert!(g.source.contains(" | "), "alternation");
}

#[test]
fn enum_mixed_types_compile_as_json_literals() {
    let schema = json!({"enum": ["on", 1, true, null]});
    let g = compile(&schema).expect("compile");
    assert!(g.source.contains("\"on\""));
    assert!(g.source.contains("1"));
    assert!(g.source.contains("true"));
    assert!(g.source.contains("null"));
}
