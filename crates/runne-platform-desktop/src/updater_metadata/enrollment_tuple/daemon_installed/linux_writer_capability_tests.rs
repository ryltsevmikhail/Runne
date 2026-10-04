use super::{VerifiedInstalledLinuxEnrollmentMeasurementFacts, now, valid_profile_runtime_pair};
#[path = "tests/fixture_signing.rs"]
mod fixture_signing;
use fixture_signing::{
    digest, fixture_linux_target, fixture_signing_material, fixture_verified_update,
};
use std::{fs, os::unix::fs::PermissionsExt as _};

#[test]
fn runtime_root_is_bound_to_its_private_profile_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("profile");
    let runtime = profile.join("bundled-runtime");
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(valid_profile_runtime_pair(&profile, &runtime));
    assert!(!valid_profile_runtime_pair(temporary.path(), &runtime));
    assert!(!valid_profile_runtime_pair(
        &profile,
        &profile.join("runtime")
    ));
}

#[test]
fn signed_linux_v2_admission_supplies_v3_runtime_facts_without_macos_tuple() {
    let hashes = ["1", "2", "3", "4"].map(|value| value.repeat(64));
    let now = now().unwrap();
    let signing = fixture_signing_material();
    let target = fixture_linux_target(now + 60, now, &hashes);
    let (verified, _) = fixture_verified_update(target, now + 60, now, &hashes, &signing);
    let measured = crate::MeasuredNativeEnrollmentArtifactsV1::test_only_from_digests(
        hashes[0].clone(),
        hashes[1].clone(),
        hashes[2].clone(),
        hashes[3].clone(),
    )
    .unwrap();
    let admission = verified.admit_native_enrollment(&measured).unwrap();
    assert!(admission.raw_v3_tuple_sha256.is_none());

    let facts = VerifiedInstalledLinuxEnrollmentMeasurementFacts::from_admission(
        [[1; 32], [2; 32], [3; 32], [4; 32]],
        &admission,
    )
    .expect("signed V2 tuple must supply V3-session measurements");
    assert_eq!(facts.release_tuple(), admission.release_tuple_sha256);
    assert_eq!(
        facts.candidate_source(),
        admission.candidate_source_sha256.unwrap()
    );
    assert_eq!(
        facts.target_manifest(),
        admission.target_manifest_sha256.unwrap()
    );
}

#[test]
fn linux_admission_reads_signed_journals_from_bundled_runtime_root() {
    let now = now().unwrap();
    let signing = fixture_signing_material();
    let hashes = ["desktop", "writer", "daemon", "contract"].map(|value| digest(value.as_bytes()));
    let (verified, _) = fixture_verified_update(
        fixture_linux_target(now + 60, now, &hashes),
        now + 60,
        now,
        &hashes,
        &signing,
    );
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("appdata");
    let runtime = profile.join("bundled-runtime");
    prepare_private_profile(&profile, &runtime);
    let paths = fixture_artifact_paths(directory.path());
    let updates = runtime.join("updates");
    persist_signed_install(&updates, &verified);
    let policy = super::super::DaemonEnrollmentPolicy {
        profile_id: "profile",
        runtime_version: "0.1.0",
        channel: "stable",
    };

    let admission = super::linux_admission::verified_linux_admission(
        &profile,
        &runtime,
        &paths,
        &signing.trust,
        &policy,
    )
    .expect("signed journals must admit from the bundled runtime root");
    assert!(
        super::linux_admission::refresh_linux_admission(
            &profile,
            &runtime,
            &paths,
            &signing.trust,
            &policy,
            &admission,
            now,
        )
        .is_some()
    );

    fs::rename(runtime.join("updates"), profile.join("updates")).unwrap();
    assert!(
        super::linux_admission::verified_linux_admission(
            &profile,
            &runtime,
            &paths,
            &signing.trust,
            &policy,
        )
        .is_none()
    );
    assert!(
        super::linux_admission::refresh_linux_admission(
            &profile,
            &runtime,
            &paths,
            &signing.trust,
            &policy,
            &admission,
            now,
        )
        .is_none()
    );
}

fn prepare_private_profile(profile: &std::path::Path, runtime: &std::path::Path) {
    fs::create_dir_all(runtime).unwrap();
    fs::set_permissions(profile, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(runtime, fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture_artifact_paths(root: &std::path::Path) -> super::super::NativeEnrollmentArtifactPathsV1 {
    let package = root.join("Runne.app");
    let macos = package.join("Contents/MacOS");
    let contract = package.join("Contents/Resources/contracts/gocode-ui-client-3/bundle.json");
    fs::create_dir_all(&macos).unwrap();
    fs::create_dir_all(contract.parent().unwrap()).unwrap();
    let desktop = macos.join("runne-desktop");
    let writer = macos.join("runne");
    let daemon = macos.join("runned");
    for (path, bytes) in [
        (&desktop, b"desktop".as_slice()),
        (&writer, b"writer"),
        (&daemon, b"daemon"),
        (&contract, b"contract"),
    ] {
        fs::write(path, bytes).unwrap();
    }
    super::super::NativeEnrollmentArtifactPathsV1::new(&desktop, &writer, &daemon, &contract)
        .unwrap()
}

fn persist_signed_install(updates: &std::path::Path, verified: &crate::VerifiedUpdateV2) {
    let metadata = crate::updater_installed_metadata::InstalledUpdateMetadataJournal::new(
        updates.join("installed-metadata.json"),
    );
    let metadata_binding = metadata.persist(verified).unwrap();
    let journal = crate::UpdateJournal::new(updates.join("install-state.json"));
    journal
        .record_staged_bound(
            "1.2.0",
            &crate::StagedUpdate {
                path: updates.join("staged.AppImage"),
                artifact_sha256: digest(b"installer"),
            },
            metadata_binding,
        )
        .unwrap();
    for state in [
        crate::UpdateInstallState::RestartRequired,
        crate::UpdateInstallState::HealthCheck,
        crate::UpdateInstallState::Committed,
    ] {
        journal.transition(state).unwrap();
    }
    let trust = crate::UpdateTrustJournal::new(updates.join("trust-state.json"));
    trust.initialize("1.0.0", "1.0.0").unwrap();
    trust.accept_metadata(7, 9, "1.2.0").unwrap();
    trust.commit_install("1.2.0").unwrap();
}
