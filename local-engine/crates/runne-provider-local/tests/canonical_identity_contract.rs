//! Public provider canonical bytes and attempt-identity preimages.
use runne_provider_local::sampling::{BackendBounds, ProfileDefaults, effective_sampling};
use runne_provider_local::structured::StructuredRequest;
use runne_provider_local::tool_parser::ToolParser;
use runne_provider_local::tool_protocol::{ToolDeclaration, render_tools_declaration};
use serde_json::json;
use sha2::{Digest, Sha256};

fn digest(bytes: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes.as_bytes()))
}

#[test]
fn common_structured_schema_bytes_and_digest() {
    let request = StructuredRequest::from_extension(&json!({
        "local-engine.structured-output.v1": {
            "schema": {"type":"object","properties":{"😀":{"type":"string"},"a":{"type":"integer"}},"required":["a"]},
            "mode":"schema-json"
        }
    })).unwrap().unwrap();
    let expected = r#"{"properties":{"a":{"type":"integer"},"😀":{"type":"string"}},"required":["a"],"type":"object"}"#;
    assert_eq!(request.canonical_schema.as_deref(), Some(expected));
    assert_eq!(request.schema_digest, digest(expected));
    println!(
        "PROVIDER schema bytes={} hash={}",
        hex::encode(expected),
        request.schema_digest
    );
}

#[test]
fn common_effective_sampling_attempt_digest() {
    let effective = effective_sampling(
        &json!({"local-engine.sampling.v1":{"stop":["é","😀"],"seed":9007199254740991_u64,"top_k":1000}}),
        ProfileDefaults::v1(), BackendBounds::llama_cpu_v1(),
    ).unwrap();
    let preimage = r#"{"min_p_milli":null,"reasoning_effort":null,"repeat_penalty_milli":null,"seed":9007199254740991,"stop":["é","😀"],"temperature_milli":700,"top_k":1000,"top_p_milli":null}"#;
    assert_eq!(effective.digest(), digest(preimage));
    println!(
        "PROVIDER sampling bytes={} hash={}",
        hex::encode(preimage),
        effective.digest()
    );
}

#[test]
fn common_tool_declaration_and_normalized_protocol_bytes() {
    let schema = r#"{"type":"object","properties":{"z":{"type":"number"},"a":{"type":"string"}}}"#;
    let block = render_tools_declaration(&[ToolDeclaration {
        name: "inspect".into(),
        description: "fixture only".into(),
        schema_json: schema.into(),
    }])
    .unwrap();
    let expected = "# Tools\nRespond with a tool_proposal item:\n- inspect({\"properties\":{\"a\":{\"type\":\"string\"},\"z\":{\"type\":\"number\"}},\"type\":\"object\"}): fixture only\n";
    assert_eq!(block.as_bytes(), expected.as_bytes());
    let payload = br#"{"name":"inspect","args":{"z":-0.0,"a":[true,null,0.000001]}}"#;
    let event = ToolParser::from_capabilities(true)
        .normalize("tool_proposal", &[0x11; 16], 42, payload)
        .unwrap()
        .unwrap();
    assert_eq!(event.tool_call_id, "11111111111111111111111111111111-002a");
    assert_eq!(event.args_json, r#"{"a":[true,null,0.000001],"z":0}"#);
    assert_eq!(digest(&block), digest(expected));
    println!(
        "PROVIDER tools bytes={} hash={}",
        hex::encode(block),
        digest(expected)
    );
    println!(
        "PROVIDER event bytes={} hash={}",
        hex::encode(&event.args_json),
        digest(&event.args_json)
    );
}
