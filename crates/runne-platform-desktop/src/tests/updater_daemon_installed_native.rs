use std::path::Path;

use crate::VerifiedDaemonNativeEnrollmentPrepare;

#[test]
fn daemon_installed_native_composition_has_no_stale_public_evidence() {
    let verify: fn(&Path, [u8; 32], [u8; 32]) -> Option<VerifiedDaemonNativeEnrollmentPrepare> =
        VerifiedDaemonNativeEnrollmentPrepare::verify_current;
    let directory = tempfile::tempdir().unwrap();

    assert!(verify(directory.path(), [0; 32], [0; 32]).is_none());
}

#[test]
fn shared_compiled_trust_never_embeds_runtime_or_bundle_bindings() {
    let sources = [
        include_str!("../updater_compiled_config.rs"),
        include_str!("../updater_metadata/enrollment_tuple/daemon_installed.rs"),
    ];

    for name in ["RUNNE_UPDATE_RUNTIME_DIGEST", "RUNNE_UPDATE_BUNDLE_SHA256"] {
        assert!(sources.iter().all(|source| !source.contains(name)));
    }
}
