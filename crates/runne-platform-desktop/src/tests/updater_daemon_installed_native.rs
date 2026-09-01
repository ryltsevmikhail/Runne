#[test]
fn daemon_installed_native_composition_has_only_peer_bound_entrypoint() {
    let installed = include_str!("../updater_metadata/enrollment_tuple/daemon_installed.rs");
    let peer = include_str!("../updater_metadata/enrollment_tuple/daemon_peer.rs");

    assert!(!installed.contains("pub fn verify_current("));
    assert!(peer.contains("pub fn verify_current_for_peer("));
    assert!(peer.contains("MacOsLocalPeerProcessIdentity::capture"));
    assert!(peer.contains("confirm_peer_macos_desktop"));
}

#[test]
fn shared_compiled_trust_never_embeds_runtime_or_bundle_bindings() {
    let sources = [
        include_str!(
            "../../../runne-api/src/provider_credential_enrollment/signed_installed_release/compiled_trust.rs"
        ),
        include_str!("../updater_metadata/enrollment_tuple/daemon_installed.rs"),
    ];

    for name in ["RUNNE_UPDATE_RUNTIME_DIGEST", "RUNNE_UPDATE_BUNDLE_SHA256"] {
        assert!(sources.iter().all(|source| !source.contains(name)));
    }
}
