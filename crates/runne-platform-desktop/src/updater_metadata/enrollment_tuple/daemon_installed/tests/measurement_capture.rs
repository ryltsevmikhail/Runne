use super::*;
use runne_macos_process_identity::MacOsLocalPeerProcessIdentity;
use std::os::unix::net::UnixStream;

#[test]
fn captured_measurements_reject_artifacts_changed_after_admission() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for role in [
        None,
        Some("runne-desktop"),
        Some("runne"),
        Some("runned"),
        Some("metadata"),
        Some("journal"),
        Some("generation"),
    ] {
        let f = fixture(now + 60);
        let mut admission = verified_admission(&f.profile, &f.paths, &f.trust, &f.policy).unwrap();
        let (stream, _other) = UnixStream::pair().unwrap();
        let peer = MacOsLocalPeerProcessIdentity::capture(&stream).unwrap();
        if role == Some("journal") {
            f.journal.clear().unwrap();
        } else if role == Some("generation") {
            admission.installed_generation += 1;
        } else if role == Some("metadata") {
            let journal = InstalledUpdateMetadataJournal::new(
                f.profile.join("updates/installed-metadata.json"),
            );
            let (mut metadata, _) = journal.read().unwrap().unwrap();
            metadata.targets.target.runtime_version = "unverified-version".into();
            std::fs::write(&f.metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        } else if let Some(role) = role {
            // In-place write keeps the opened inode while changing its measured bytes.
            std::fs::write(
                f.daemon.parent().unwrap().join(role),
                b"changed native artifact",
            )
            .unwrap();
        }
        let prepared = VerifiedDaemonNativeEnrollmentPrepare::peer_bound(
            peer, [7; 32], f.paths, admission, f.profile,
        );
        let facts = VerifiedInstalledEnrollmentMeasurementFacts::from_revalidated(&prepared);
        assert_eq!(facts.is_some(), role.is_none(), "role {role:?}");
    }
}
