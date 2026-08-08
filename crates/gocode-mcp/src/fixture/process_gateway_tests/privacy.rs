#[test]
fn process_gateway_has_no_public_activation_constructor() {
    let root = include_str!("../../lib.rs");
    let (_, fixture_exports) = root
        .split_once("pub use fixture::{")
        .expect("lib root must export fixture symbols");
    let (fixture_exports, _) = fixture_exports
        .split_once("};")
        .expect("fixture export block must close");

    assert!(!fixture_exports.contains("McpProcessToolGateway"));
    assert!(!fixture_exports.contains("FixtureProcessApprovalAuthority"));
}

#[test]
fn removed_process_call_is_not_available_to_fixture_tests() {
    let source = include_str!("../process.rs");
    assert!(!source.contains("McpProcessCall"));
    assert!(!source.contains("without_process_approval"));
}

#[test]
fn generation_lease_remains_private() {
    let source = include_str!("../../discovery/generation.rs");
    assert!(source.contains("pub(crate) struct McpGenerationReadPermit"));
    assert!(!source.contains("pub struct McpGenerationReadPermit"));
}
