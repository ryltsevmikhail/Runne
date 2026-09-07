//! Tool proposals (Plan Task 11): manifest-qualified proposals
//! normalize into bounded tool events with deterministic ids;
//! declaration rendering is byte-stable.

mod common;

use common::{AllowPermit, SettlementPort, adapter, admit_model, call};
use runne_provider_local::port::ProviderPort;
use runne_provider_local::tool_protocol::{
    ToolDeclaration, derive_tool_call_id, render_tools_declaration,
};

#[test]
fn declaration_rendering_is_deterministic() {
    let tools = [
        ToolDeclaration {
            name: "get_weather".into(),
            description: "Look up weather".into(),
            schema_json: r#"{"type":"object","properties":{"city":{"type":"string"}}}"#.into(),
        },
        ToolDeclaration {
            name: "run_query".into(),
            description: "Run a query".into(),
            schema_json: r#"{"properties":{"q":{"type":"string"}},"type":"object"}"#.into(),
        },
    ];
    let r1 = render_tools_declaration(&tools).expect("render");
    let r2 = render_tools_declaration(&tools).expect("render");
    assert_eq!(r1, r2, "byte-stable");
    assert!(r1.contains("- get_weather("));
    // Schema canonicalization sorted keys of the second tool.
    assert!(r1.contains(r#"{"properties":{"q":{"type":"string"}},"type":"object"}"#));
    // Empty declaration list renders empty (tools off the wire).
    assert_eq!(render_tools_declaration(&[]).expect("empty"), "");
}

#[test]
fn tool_call_id_is_sequence_bound_and_stable() {
    let stream = [3u8; 16];
    let id0 = derive_tool_call_id(&stream, 0);
    let id0_again = derive_tool_call_id(&stream, 0);
    let id1 = derive_tool_call_id(&stream, 1);
    assert_eq!(id0, id0_again, "replay-stable");
    assert_ne!(id0, id1, "sequence-scoped");
}

#[test]
fn adapter_prepare_remains_tool_agnostic() {
    // Tool qualification is manifest/protocol level; the plain prepare
    // path is unaffected and stays effect-free.
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let p = a.prepare(&c).expect("prepare");
    assert_eq!(p.model_identity, "m1");
}
