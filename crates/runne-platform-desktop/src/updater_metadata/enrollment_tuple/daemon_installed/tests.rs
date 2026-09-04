use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::updater_installed_metadata::InstalledUpdateMetadataJournal;
use crate::{
    NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleV2, StagedUpdate,
    UpdateInstallState, UpdateJournal, UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2,
    UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetV2Binding, UpdateTargetsRoleV2,
    UpdateTimestampRoleV2, UpdateTrustJournal, UpdateTrustRootV2, verify_update_v2,
};

use super::*;

#[path = "tests/measurement_capture.rs"]
mod measurement_capture;

struct Fixture {
    _directory: tempfile::TempDir,
    profile: PathBuf,
    paths: NativeEnrollmentArtifactPathsV1,
    trust: UpdateTrustRootV2,
    policy: DaemonEnrollmentPolicy<'static>,
    release: [u8; 32],
    qualification: [u8; 32],
    artifact: String,
    journal: UpdateJournal,
    trust_journal: UpdateTrustJournal,
    metadata_path: PathBuf,
    daemon: PathBuf,
    contract: PathBuf,
}

struct FixtureIdentity;

struct RejectingIdentity;

impl DaemonIdentityVerifier for FixtureIdentity {
    fn confirm(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
        admission: &NativeEnrollmentTupleAdmission,
    ) -> bool {
        paths.confirm_current_daemon(admission.daemon_sha256).is_ok()
    }
}

impl DaemonIdentityVerifier for RejectingIdentity {
    fn confirm(
        &self,
        _paths: &NativeEnrollmentArtifactPathsV1,
        _admission: &NativeEnrollmentTupleAdmission,
    ) -> bool {
        false
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fixture(expires_at: u64) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile");
    let macos = directory.path().join("Runne.app/Contents/MacOS");
    let contract = directory
        .path()
        .join("Runne.app/Contents/Resources/contracts/gocode-ui-client-2/bundle.json");
    std::fs::create_dir_all(contract.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&macos).unwrap();
    let desktop = macos.join("runne-desktop");
    let writer = macos.join("runne");
    let daemon = macos.join("runned");
    for (path, bytes) in [
        (&desktop, b"desktop".as_slice()),
        (&writer, b"writer"),
        (&daemon, b"daemon"),
        (&contract, b"contract"),
    ] {
        std::fs::write(path, bytes).unwrap();
    }
    let hashes = [
        digest(b"desktop"),
        digest(b"writer"),
        digest(b"daemon"),
        digest(b"contract"),
    ];
    let roots = [
        SigningKey::from_bytes(&[11; 32]),
        SigningKey::from_bytes(&[12; 32]),
        SigningKey::from_bytes(&[13; 32]),
    ];
    let timestamp = SigningKey::from_bytes(&[14; 32]);
    let snapshot = SigningKey::from_bytes(&[15; 32]);
    let trust = UpdateTrustRootV2::from_keys(
        [
            ("root-a", roots[0].verifying_key().to_bytes()),
            ("root-b", roots[1].verifying_key().to_bytes()),
            ("root-c", roots[2].verifying_key().to_bytes()),
        ],
        ("timestamp", timestamp.verifying_key().to_bytes()),
        ("snapshot", snapshot.verifying_key().to_bytes()),
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut target = UpdateTargetV2 {
        product_id: "com.runne.desktop".into(), version: "1.2.0".into(), platform: "macos".into(), arch: "arm64".into(),
        artifact_sha256: digest(b"installer"), artifact_size: 1, artifact_url: "https://updates.example.test/runne.dmg".into(),
        release_candidate_sha256: digest(b"candidate"), min_os: "macos-13".into(), profile_id: "profile".into(), bundle_sha256: hashes[3].clone(),
        runtime_version: "0.1.0".into(), runtime_digest: hashes[2].clone(), channel: "stable".into(),
        published_at_unix_seconds: now.saturating_sub(5), expires_at_unix_seconds: expires_at, rollback_floor: "1.0.0".into(), native_enrollment_tuple: None, native_enrollment_tuple_v3: None,
    };
    let tuple = NativeEnrollmentTupleV2::new_macos(
        target.release_candidate_sha256.clone(), hashes[0].clone(), hashes[1].clone(), hashes[2].clone(), hashes[3].clone(),
        "com.runne.desktop", "RUNNE12345", "3".repeat(40), "com.runne.writer", "RUNNE12345", "1".repeat(40),
        "com.runne.daemon", "RUNNE12345", "2".repeat(40), &target,
    ).unwrap();
    let qualification = NativeEnrollmentQualificationRowV1::new(
        &target, &tuple, digest(b"fixture-only-qualification"), now.saturating_sub(1), expires_at,
    ).unwrap();
    target.native_enrollment_tuple = Some(tuple.with_qualification(&target, qualification).unwrap());
    let encoded = serde_json::to_value(&target.native_enrollment_tuple).unwrap();
    let qualification = hex::decode(encoded["nativeEnrollmentQualification"]["bindingSha256"].as_str().unwrap()).unwrap().try_into().unwrap();
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 { version: 8, expires_at_unix_seconds: expires_at, target };
    let snapshot_role = UpdateSnapshotRoleV2 { version: 9, expires_at_unix_seconds: expires_at, targets_version: 8 };
    let timestamp_role = UpdateTimestampRoleV2 { version: 10, expires_at_unix_seconds: expires_at, snapshot_version: 9 };
    let metadata = UpdateMetadataV2 {
        schema_version: 2, root: root.clone(), targets: targets.clone(), snapshot: snapshot_role.clone(), timestamp: timestamp_role.clone(),
        root_signatures: signatures(&roots, &root), targets_signatures: signatures(&roots, &targets),
        snapshot_signature: signed(&snapshot, &snapshot_role), timestamp_signature: signed(&timestamp, &timestamp_role),
    };
    let binding = UpdateTargetV2Binding {
        product_id: "com.runne.desktop", platform: "macos", arch: "arm64", min_os: "macos-13", profile_id: "profile",
        bundle_sha256: &hashes[3], runtime_version: "0.1.0", runtime_digest: &hashes[2], channel: "stable",
    };
    let verified = verify_update_v2(&metadata, &trust, &binding, now, "1.2.0", "1.0.0").unwrap();
    let release = runne_api::verify_signed_update_metadata_v2(&metadata, &trust, now)
        .unwrap()
        .qualified_release_candidate()
        .unwrap()
        .release_binding_digest();
    let updates = profile.join("updates");
    let metadata_journal = InstalledUpdateMetadataJournal::new(updates.join("installed-metadata.json"));
    let metadata_binding = metadata_journal.persist(&verified).unwrap();
    let journal = UpdateJournal::new(updates.join("install-state.json"));
    let artifact = digest(b"installer");
    commit_record(&journal, &updates, &artifact, &metadata_binding);
    let trust_journal = UpdateTrustJournal::new(updates.join("trust-state.json"));
    trust_journal.initialize("1.0.0", "1.0.0").unwrap();
    trust_journal.accept_metadata(7, 9, "1.2.0").unwrap();
    trust_journal.commit_install("1.2.0").unwrap();
    Fixture {
        _directory: directory, profile, paths: NativeEnrollmentArtifactPathsV1::new(&desktop, &writer, &daemon, &contract).unwrap(), trust,
        policy: DaemonEnrollmentPolicy { profile_id: "profile", runtime_version: "0.1.0", channel: "stable" }, release, qualification, artifact,
        journal, trust_journal, metadata_path: updates.join("installed-metadata.json.1.json"), daemon, contract,
    }
}

fn commit_record(journal: &UpdateJournal, updates: &Path, artifact: &str, metadata_binding: &str) {
    journal.record_staged_bound("1.2.0", &StagedUpdate { path: updates.join("staged.dmg"), artifact_sha256: artifact.into() }, metadata_binding.into()).unwrap();
    for state in [UpdateInstallState::RestartRequired, UpdateInstallState::HealthCheck, UpdateInstallState::Committed] {
        journal.transition(state).unwrap();
    }
}

fn signatures<T: serde::Serialize>(keys: &[SigningKey; 3], value: &T) -> Vec<UpdateSignatureV2> {
    ["root-a", "root-b"].into_iter().zip(keys).map(|(key_id, key)| UpdateSignatureV2 { key_id: key_id.into(), signature: signed(key, value) }).collect()
}

fn signed<T: serde::Serialize>(key: &SigningKey, value: &T) -> String {
    hex::encode(key.sign(&serde_json::to_vec(value).unwrap()).to_bytes())
}

fn verify(fixture: &Fixture) -> Option<VerifiedDaemonNativeEnrollmentPrepare> {
    verify_with(&input(fixture, fixture.release, fixture.qualification), &FixtureIdentity, || {})
}

pub(in crate::updater_metadata) struct SignedFixtureAdmission {
    pub(in crate::updater_metadata) admission: NativeEnrollmentTupleAdmission,
    pub(in crate::updater_metadata) release: [u8; 32],
    pub(in crate::updater_metadata) qualification: [u8; 32],
    pub(in crate::updater_metadata) expires_at: u64,
}

pub(in crate::updater_metadata) fn signed_fixture_admission() -> SignedFixtureAdmission {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let fixture = fixture(now + 60);
    SignedFixtureAdmission {
        admission: verified_admission(&fixture.profile, &fixture.paths, &fixture.trust, &fixture.policy)
            .unwrap(),
        release: fixture.release,
        qualification: fixture.qualification,
        expires_at: now + 60,
    }
}

fn input(
    fixture: &Fixture,
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
) -> DaemonVerificationInput<'_> {
    DaemonVerificationInput {
        profile_directory: &fixture.profile,
        paths: &fixture.paths,
        trust: &fixture.trust,
        policy: &fixture.policy,
        release_tuple_digest,
        qualification_binding_digest,
    }
}

#[test]
fn fixture_composition_admits_only_a_current_signed_qualified_release() {
    let fixture = fixture(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60);
    assert!(fixture.paths.measure().is_ok());
    let admission = verified_admission(&fixture.profile, &fixture.paths, &fixture.trust, &fixture.policy).unwrap();
    assert!(FixtureIdentity.confirm(&fixture.paths, &admission));
    assert!(admission.qualification.matches_exact(fixture.release, fixture.qualification, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()), "{:?}", admission.qualification);
    assert!(verify(&fixture).is_some());
    assert!(verify_with(&input(&fixture, fixture.release, fixture.qualification), &RejectingIdentity, || {}).is_none());
    assert!(verify_with(&input(&fixture, [0; 32], fixture.qualification), &FixtureIdentity, || {}).is_none());
    assert!(verify_with(&input(&fixture, fixture.release, [0; 32]), &FixtureIdentity, || {}).is_none());
}

#[test]
fn qualified_admission_retains_distinct_measurement_sources() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let fixture = fixture(now + 60);
    let admission = verified_admission(
        &fixture.profile,
        &fixture.paths,
        &fixture.trust,
        &fixture.policy,
    )
    .unwrap();
    let candidate = admission.candidate_source_sha256.unwrap();
    let manifest = admission.target_manifest_sha256.unwrap();
    let qualification = admission
        .qualification
        .retained_qualification_binding_digest()
        .unwrap();
    let sources = [candidate, manifest, qualification, admission.release_tuple_sha256];
    for (index, source) in sources.iter().enumerate() {
        assert!(sources[index + 1..].iter().all(|other| other != source));
    }
}

#[test]
fn fixture_composition_closes_for_noncommitted_corrupt_binding_rollback_or_expiry() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let first = fixture(now + 60); first.journal.clear().unwrap(); assert!(verify(&first).is_none());
    let binding = fixture(now + 60);
    binding.journal.clear().unwrap();
    commit_record(&binding.journal, &binding.profile.join("updates"), &binding.artifact, &"0".repeat(64));
    assert!(verify(&binding).is_none());
    let second = fixture(now + 60); std::fs::write(&second.metadata_path, b"{").unwrap(); assert!(verify(&second).is_none());
    let third = fixture(now + 60); third.trust_journal.accept_metadata(8, 10, "1.2.0").unwrap(); assert!(verify(&third).is_none());
    let expired = fixture(now + 60);
    assert!(verified_admission_at(&expired.profile, &expired.paths, &expired.trust, &expired.policy, now + 61).is_none());
}

#[test]
fn final_phase_closes_when_journal_or_artifacts_change() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let first = fixture(now + 60);
    assert!(verify_with(&input(&first, first.release, first.qualification), &FixtureIdentity, || first.journal.clear().unwrap()).is_none());
    let second = fixture(now + 60);
    assert!(verify_with(&input(&second, second.release, second.qualification), &FixtureIdentity, || std::fs::write(&second.daemon, b"changed").unwrap()).is_none());
    let third = fixture(now + 60);
    assert!(verify_with(&input(&third, third.release, third.qualification), &FixtureIdentity, || std::fs::write(&third.contract, b"changed").unwrap()).is_none());
}

#[test]
fn retained_admission_refresh_closes_after_mint_journal_trust_or_expiry_change() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let journal = fixture(now + 60);
    let retained = verified_admission(&journal.profile, &journal.paths, &journal.trust, &journal.policy).unwrap();
    assert!(refresh_retained_admission_at(&journal.profile, &journal.paths, &journal.trust, &journal.policy, &retained, now).is_some());
    journal.journal.clear().unwrap();
    assert!(refresh_retained_admission_at(&journal.profile, &journal.paths, &journal.trust, &journal.policy, &retained, now).is_none());

    let trust = fixture(now + 60);
    let retained = verified_admission(&trust.profile, &trust.paths, &trust.trust, &trust.policy).unwrap();
    trust.trust_journal.accept_metadata(8, 10, "1.2.0").unwrap();
    assert!(refresh_retained_admission_at(&trust.profile, &trust.paths, &trust.trust, &trust.policy, &retained, now).is_none());

    let expiry = fixture(now + 60);
    let retained = verified_admission(&expiry.profile, &expiry.paths, &expiry.trust, &expiry.policy).unwrap();
    assert!(refresh_retained_admission_at(&expiry.profile, &expiry.paths, &expiry.trust, &expiry.policy, &retained, now + 61).is_none());
}
