use super::super::http_startup_support::replay_cursor_integrity_secret;
use super::provider_credentials::runtime_capabilities;
use crate::replay_key::ReplayIntegrityKeyManager;

mod replay_cursor_fixture;

#[test]
fn root_capability_requires_the_verified_protected_authority_path() {
    assert_eq!(
        runtime_capabilities(false, true, true),
        runne_runtime::bundle::BASE_RUNTIME_CAPABILITIES
    );
    assert_eq!(
        runtime_capabilities(true, false, true),
        runne_runtime::bundle::BASE_RUNTIME_CAPABILITIES
    );
    #[cfg(feature = "desktop-protected")]
    assert_eq!(
        runtime_capabilities(true, true, false),
        runne_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES
    );
    #[cfg(feature = "desktop-protected")]
    assert_eq!(
        runtime_capabilities(true, true, true),
        runne_runtime::bundle::ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
    );
}

#[test]
fn replay_cursor_hmac_secret_matches_the_pre_rename_domain_after_key_reload() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay-integrity.key");
    std::fs::write(&path, (0_u8..32).collect::<Vec<_>>()).unwrap();

    let restarted = ReplayIntegrityKeyManager::load_or_provision(&path).unwrap();
    assert_eq!(
        hex::encode(replay_cursor_integrity_secret(&restarted)),
        "3f42d93ed3fb9675b473e0ab68c422ca585a1041c25e257254412a5f9911db37"
    );
}
