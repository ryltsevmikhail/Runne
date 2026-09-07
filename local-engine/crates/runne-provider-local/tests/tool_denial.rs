//! Tool denial (Plan Task 11): unqualified proposals reject the
//! stream, malformed/oversized payloads reject typed, and nothing in
//! the parser executes a tool — output is data only.

use runne_provider_local::error::ProviderError;
use runne_provider_local::tool_parser::ToolParser;
use runne_provider_local::tool_protocol::ToolProtocolError;

fn payload(name: &str, args: &str) -> Vec<u8> {
    format!(r#"{{"name":"{name}","args":{args}}}"#).into_bytes()
}

#[test]
fn unqualified_manifest_rejects_any_proposal() {
    let parser = ToolParser::from_capabilities(false);
    let err = parser
        .normalize("tool_proposal", &[3; 16], 0, &payload("t", "{}"))
        .expect_err("not qualified");
    assert_eq!(
        err,
        ProviderError::ToolProtocol(ToolProtocolError::NotQualified)
    );
}

#[test]
fn non_tool_kinds_pass_through_untouched() {
    let parser = ToolParser::from_capabilities(true);
    for kind in ["text", "usage", "finish"] {
        assert_eq!(
            parser.normalize(kind, &[3; 16], 0, b"{}").expect("none"),
            None
        );
    }
}

#[test]
fn malformed_proposals_reject_typed() {
    let parser = ToolParser::from_capabilities(true);
    let err = parser
        .normalize("tool_proposal", &[3; 16], 0, b"not json")
        .expect_err("bad json");
    assert_eq!(
        err,
        ProviderError::ToolProtocol(ToolProtocolError::Malformed)
    );
    // Missing name.
    let err = parser
        .normalize("tool_proposal", &[3; 16], 0, br#"{"args":{}}"#)
        .expect_err("no name");
    assert_eq!(
        err,
        ProviderError::ToolProtocol(ToolProtocolError::Malformed)
    );
    // Empty name.
    let err = parser
        .normalize("tool_proposal", &[3; 16], 0, br#"{"name":"","args":{}}"#)
        .expect_err("empty name");
    assert_eq!(
        err,
        ProviderError::ToolProtocol(ToolProtocolError::Malformed)
    );
}

#[test]
fn oversized_name_and_args_reject() {
    let parser = ToolParser::from_capabilities(true);
    let long_name = "n".repeat(129);
    let err = parser
        .normalize("tool_proposal", &[3; 16], 0, &payload(&long_name, "{}"))
        .expect_err("name");
    assert_eq!(
        err,
        ProviderError::ToolProtocol(ToolProtocolError::OverLimitName)
    );
    let big_args = format!(r#"{{"blob":"{}"}}"#, "x".repeat(9 * 1024));
    let err = parser
        .normalize("tool_proposal", &[3; 16], 0, &payload("t", &big_args))
        .expect_err("args");
    assert_eq!(
        err,
        ProviderError::ToolProtocol(ToolProtocolError::OverLimitArgs)
    );
}

#[test]
fn valid_proposal_normalizes_to_data_only() {
    let parser = ToolParser::from_capabilities(true);
    let event = parser
        .normalize(
            "tool_proposal",
            &[3; 16],
            5,
            &payload("run_query", r#"{"q":"go"}"#),
        )
        .expect("normalized")
        .expect("some");
    assert_eq!(event.name, "run_query");
    assert_eq!(event.args_json, r#"{"q":"go"}"#);
    assert_eq!(
        event.tool_call_id,
        runne_provider_local::tool_protocol::derive_tool_call_id(&[3; 16], 5)
    );
    // The event is inert data: it carries no executor and the parser
    // exposes no run/invoke surface — execution is ToolGateway-only.
    let _ = std::any::type_name::<ToolParser>();
}
