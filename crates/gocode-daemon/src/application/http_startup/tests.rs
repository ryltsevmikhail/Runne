use super::runtime_capabilities;

#[test]
fn root_capability_requires_the_verified_protected_authority_path() {
    assert_eq!(
        runtime_capabilities(false, true),
        gocode_runtime::bundle::BASE_RUNTIME_CAPABILITIES
    );
    assert_eq!(
        runtime_capabilities(true, false),
        gocode_runtime::bundle::BASE_RUNTIME_CAPABILITIES
    );
    #[cfg(feature = "desktop-protected")]
    assert_eq!(
        runtime_capabilities(true, true),
        gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES
    );
}
