use super::{
    VerifiedInstalledLinuxEnrollmentMeasurementFacts, now, valid_profile_runtime_pair,
};
#[path = "tests/fixture_signing.rs"]
mod fixture_signing;
use fixture_signing::{fixture_linux_target, fixture_signing_material, fixture_verified_update};
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
