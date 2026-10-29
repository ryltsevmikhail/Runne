use super::runtime_authority_matches_node;

#[test]
fn accepts_same_uuid_in_runtime_hex_and_node_uuid_forms() {
    let bytes = [0x31_u8; 16];
    let authority = hex::encode(bytes);
    let node = uuid::Uuid::from_bytes(bytes).to_string();

    assert_eq!(authority.len(), 32);
    assert_eq!(node.len(), 36);
    assert!(runtime_authority_matches_node(&authority, &node));
}

#[test]
fn rejects_malformed_or_different_runtime_authority() {
    let bytes = [0x31_u8; 16];
    let other_bytes = [0x32_u8; 16];
    let authority = hex::encode(bytes);
    let node = uuid::Uuid::from_bytes(bytes).to_string();
    let other_node = uuid::Uuid::from_bytes(other_bytes).to_string();

    assert!(!runtime_authority_matches_node("not-a-uuid", &node));
    assert!(!runtime_authority_matches_node(&authority, "not-a-uuid"));
    assert!(!runtime_authority_matches_node(&authority, &other_node));
}

#[test]
fn recovery_routes_legacy_and_coding_profiles_but_not_text_or_unknown_profiles() {
    assert!(super::recovery_tool_profile("runne-linux-agent-tools-v1"));
    assert!(super::recovery_tool_profile(
        "runne-deepseek-responses-tools/1"
    ));
    for profile in [
        "gocode-deepseek-responses-text/1",
        "gocode-openai-responses-background-text/1",
        "",
        "runne-deepseek-responses-tools/2",
    ] {
        assert!(!super::recovery_tool_profile(profile));
    }
}
