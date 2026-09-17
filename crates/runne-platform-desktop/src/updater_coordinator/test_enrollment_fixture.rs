use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::{
    ConfirmedInstalledNativeEnrollment, MeasuredNativeEnrollmentArtifactsV1,
    NativeEnrollmentTupleV2, UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2,
    UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetsRoleV2, UpdateTimestampRoleV2,
    verify_update_v2,
};

/// Opaque real coordinator/confirmation fixture for post-fence integration tests.
#[doc(hidden)]
pub struct TestOnlyEnrollmentUpdaterFixture {
    coordinator: UpdateCoordinator,
    confirmed: ConfirmedInstalledNativeEnrollment,
    revalidation: TestOnlyEnrollmentRevalidation,
}

/// Opaque test-only witness for the fixture's independently measured files.
#[doc(hidden)]
pub struct TestOnlyEnrollmentRevalidation(MeasuredNativeEnrollmentArtifactsV1);

impl TestOnlyEnrollmentRevalidation {
    pub fn revalidate(
        &self,
        coordinator: &UpdateCoordinator,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<bool, UpdateCoordinatorError> {
        coordinator.test_support_revalidate_confirmed_at(
            confirmed,
            unix_seconds(),
            &self.0,
        )
    }
}

impl TestOnlyEnrollmentUpdaterFixture {
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        UpdateCoordinator,
        ConfirmedInstalledNativeEnrollment,
        TestOnlyEnrollmentRevalidation,
    ) {
        (self.coordinator, self.confirmed, self.revalidation)
    }
}

#[doc(hidden)]
#[must_use]
pub fn test_only_current_enrollment_updater_fixture(
    directory: &Path,
) -> TestOnlyEnrollmentUpdaterFixture {
    enrollment_updater_fixture(directory, unix_seconds().saturating_add(60))
}

#[doc(hidden)]
#[must_use]
pub fn test_only_expired_enrollment_updater_fixture(
    directory: &Path,
) -> TestOnlyEnrollmentUpdaterFixture {
    enrollment_updater_fixture(directory, unix_seconds().saturating_sub(1))
}

fn enrollment_updater_fixture(
    directory: &Path,
    expires_at: u64,
) -> TestOnlyEnrollmentUpdaterFixture {
    let files = ["desktop", "writer", "daemon", "contract"].map(|name| directory.join(name));
    for (path, bytes) in files.iter().zip([
        b"desktop".as_slice(), b"writer", b"daemon", b"contract",
    ]) {
        std::fs::write(path, bytes).expect("write measurement fixture");
    }
    let hashes = files.each_ref().map(|path| digest(&std::fs::read(path).expect("read fixture")));
    let roots = [1_u8, 2, 3].map(|byte| SigningKey::from_bytes(&[byte; 32]));
    let timestamp = SigningKey::from_bytes(&[4; 32]);
    let snapshot = SigningKey::from_bytes(&[5; 32]);
    let trust = UpdateTrustRootV2::from_keys(
        [
            ("root-a", roots[0].verifying_key().to_bytes()),
            ("root-b", roots[1].verifying_key().to_bytes()),
            ("root-c", roots[2].verifying_key().to_bytes()),
        ],
        ("timestamp", timestamp.verifying_key().to_bytes()),
        ("snapshot", snapshot.verifying_key().to_bytes()),
    );
    let now = unix_seconds();
    let installer = digest(b"installer");
    let mut target = UpdateTargetV2 {
        product_id: "com.runne.desktop".into(), version: "1.2.0".into(), platform: "linux".into(),
        arch: "x86_64".into(), artifact_sha256: installer.clone(), artifact_size: 10,
        artifact_url: "https://updates.example.test/runne.AppImage".into(),
        release_candidate_sha256: "f".repeat(64), min_os: "ubuntu-22.04".into(),
        profile_id: "profile".into(), bundle_sha256: hashes[3].clone(),
        runtime_version: "0.1.0".into(), runtime_digest: "b".repeat(64), channel: "stable".into(),
        published_at_unix_seconds: now.saturating_sub(5), expires_at_unix_seconds: expires_at,
        rollback_floor: "1.0.0".into(), native_enrollment_tuple: None, native_enrollment_tuple_v3: None, qualification_bootstrap_client_v1: None,
    };
    target.native_enrollment_tuple = Some(NativeEnrollmentTupleV2::new(
        target.release_candidate_sha256.clone(), hashes[0].clone(), hashes[1].clone(),
        hashes[2].clone(), hashes[3].clone(), &target,
    ).expect("native tuple"));
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 { version: 8, expires_at_unix_seconds: expires_at, target };
    let snapshot_role = UpdateSnapshotRoleV2 { version: 9, expires_at_unix_seconds: expires_at, targets_version: 8 };
    let timestamp_role = UpdateTimestampRoleV2 { version: 10, expires_at_unix_seconds: expires_at, snapshot_version: 9 };
    let metadata = UpdateMetadataV2 {
        schema_version: 2, root: root.clone(), targets: targets.clone(), snapshot: snapshot_role.clone(),
        timestamp: timestamp_role.clone(),
        root_signatures: roots[..2].iter().enumerate().map(|(index, key)| UpdateSignatureV2 {
            key_id: ["root-a", "root-b"][index].into(), signature: sign(key, &root),
        }).collect(),
        targets_signatures: roots[..2].iter().enumerate().map(|(index, key)| UpdateSignatureV2 {
            key_id: ["root-a", "root-b"][index].into(), signature: sign(key, &targets),
        }).collect(),
        snapshot_signature: sign(&snapshot, &snapshot_role),
        timestamp_signature: sign(&timestamp, &timestamp_role),
    };
    let runtime = "b".repeat(64);
    let verified = verify_update_v2(
        &metadata, &trust,
        &UpdateTargetV2Binding { product_id: "com.runne.desktop", platform: "linux", arch: "x86_64",
            min_os: "ubuntu-22.04", profile_id: "profile", bundle_sha256: &hashes[3],
            runtime_version: "0.1.0", runtime_digest: &runtime, channel: "stable" },
        expires_at.min(now).saturating_sub(1), "1.0.0", "1.0.0",
    ).expect("verified update");
    let coordinator = UpdateCoordinator::new(trust, binding(&hashes[3]), directory).expect("coordinator");
    let metadata_binding = coordinator.installed_metadata.persist(&verified).expect("installed metadata");
    coordinator.journal.record_staged_bound(
        "1.2.0", &StagedUpdate { path: directory.join("staged.update"), artifact_sha256: installer }, metadata_binding,
    ).expect("staged");
    coordinator.trust_journal.initialize("1.0.0", "1.0.0").expect("trust");
    coordinator.prepare_restart(0, false).expect("prepare");
    coordinator.begin_health_check().expect("health");
    coordinator.complete_health(true, "1.2.0").expect("complete");
    let artifacts = MeasuredNativeEnrollmentArtifactsV1::test_only_from_digests(
        hashes[0].clone(), hashes[1].clone(), hashes[2].clone(), hashes[3].clone(),
    ).expect("artifacts");
    let admission = verified.admit_native_enrollment(&artifacts).expect("admission");
    let confirmed = ConfirmedInstalledNativeEnrollment::test_only_from_admission(admission);
    TestOnlyEnrollmentUpdaterFixture {
        coordinator,
        confirmed,
        revalidation: TestOnlyEnrollmentRevalidation(artifacts),
    }
}

fn binding(bundle: &str) -> UpdateTargetBindingConfig {
    UpdateTargetBindingConfig { product_id: "com.runne.desktop".into(), platform: "linux".into(),
        arch: "x86_64".into(), min_os: "ubuntu-22.04".into(), profile_id: "profile".into(),
        bundle_sha256: bundle.into(), runtime_version: "0.1.0".into(),
        runtime_digest: "b".repeat(64), channel: "stable".into() }
}

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn unix_seconds() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs() }
fn sign<T: serde::Serialize>(key: &SigningKey, value: &T) -> String {
    hex::encode(key.sign(&serde_json::to_vec(value).expect("encode role")).to_bytes())
}
