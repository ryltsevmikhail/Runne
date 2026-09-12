use super::*;
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleV2, UpdateMetadataV2,
    UpdateRootRoleV2, UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2,
    UpdateTargetV2Binding, UpdateTargetsRoleV2, UpdateTimestampRoleV2, verify_update_v2,
};

fn binding() -> UpdateTargetBindingConfig {
    UpdateTargetBindingConfig {
        product_id: "com.runne.desktop".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        min_os: "ubuntu-22.04".into(),
        profile_id: "profile".into(),
        bundle_sha256: "a".repeat(64),
        runtime_version: "0.1.0".into(),
        runtime_digest: "b".repeat(64),
        channel: "stable".into(),
    }
}

fn coordinator(directory: &Path) -> UpdateCoordinator {
    let root_a = SigningKey::from_bytes(&[1; 32]);
    let root_b = SigningKey::from_bytes(&[2; 32]);
    let root_c = SigningKey::from_bytes(&[3; 32]);
    let timestamp = SigningKey::from_bytes(&[4; 32]);
    let snapshot = SigningKey::from_bytes(&[5; 32]);
    UpdateCoordinator::new(
        UpdateTrustRootV2::from_keys(
            [
                ("root-a", root_a.verifying_key().to_bytes()),
                ("root-b", root_b.verifying_key().to_bytes()),
                ("root-c", root_c.verifying_key().to_bytes()),
            ],
            ("timestamp", timestamp.verifying_key().to_bytes()),
            ("snapshot", snapshot.verifying_key().to_bytes()),
        ),
        binding(),
        directory,
    )
    .unwrap()
}

fn signed_role<T: serde::Serialize>(key: &SigningKey, role: &T) -> String {
    hex::encode(key.sign(&serde_json::to_vec(role).unwrap()).to_bytes())
}

fn verified_update() -> VerifiedUpdateV2 {
    let roots = [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    ];
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
    let mut target = UpdateTargetV2 {
        product_id: "com.runne.desktop".into(),
        version: "1.2.0".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        artifact_sha256: "c".repeat(64),
        artifact_size: 10,
        artifact_url: "https://updates.example.test/runne.AppImage".into(),
        release_candidate_sha256: "f".repeat(64),
        min_os: "ubuntu-22.04".into(),
        profile_id: "profile".into(),
        bundle_sha256: "a".repeat(64),
        runtime_version: "0.1.0".into(),
        runtime_digest: "b".repeat(64),
        channel: "stable".into(),
        published_at_unix_seconds: 100,
        expires_at_unix_seconds: 500,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None, native_enrollment_tuple_v3: None, qualification_bootstrap_client_v1: None,
    };
    target.native_enrollment_tuple = Some(
        NativeEnrollmentTupleV2::new(
            target.release_candidate_sha256.clone(),
            "b".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            target.bundle_sha256.clone(),
            &target,
        )
        .unwrap(),
    );
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 {
        version: 8,
        expires_at_unix_seconds: 500,
        target,
    };
    let snapshot_role = UpdateSnapshotRoleV2 {
        version: 9,
        expires_at_unix_seconds: 500,
        targets_version: 8,
    };
    let timestamp_role = UpdateTimestampRoleV2 {
        version: 10,
        expires_at_unix_seconds: 500,
        snapshot_version: 9,
    };
    let metadata = UpdateMetadataV2 {
        schema_version: 2,
        root: root.clone(),
        targets: targets.clone(),
        snapshot: snapshot_role.clone(),
        timestamp: timestamp_role.clone(),
        root_signatures: roots[..2]
            .iter()
            .enumerate()
            .map(|(index, key)| UpdateSignatureV2 {
                key_id: ["root-a", "root-b"][index].into(),
                signature: signed_role(key, &root),
            })
            .collect(),
        targets_signatures: roots[..2]
            .iter()
            .enumerate()
            .map(|(index, key)| UpdateSignatureV2 {
                key_id: ["root-a", "root-b"][index].into(),
                signature: signed_role(key, &targets),
            })
            .collect(),
        snapshot_signature: signed_role(&snapshot, &snapshot_role),
        timestamp_signature: signed_role(&timestamp, &timestamp_role),
    };
    let binding = UpdateTargetV2Binding {
        product_id: "com.runne.desktop",
        platform: "linux",
        arch: "x86_64",
        min_os: "ubuntu-22.04",
        profile_id: "profile",
        bundle_sha256: &metadata.targets.target.bundle_sha256,
        runtime_version: "0.1.0",
        runtime_digest: &metadata.targets.target.runtime_digest,
        channel: "stable",
    };
    verify_update_v2(&metadata, &trust, &binding, 100, "1.0.0", "1.0.0").unwrap()
}

fn artifacts() -> MeasuredNativeEnrollmentArtifactsV1 {
    MeasuredNativeEnrollmentArtifactsV1::test_only_from_digests(
        "b".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
        "a".repeat(64),
    )
    .unwrap()
}

fn record(coordinator: &UpdateCoordinator, directory: &Path) {
    let metadata_sha256 = coordinator
        .installed_metadata
        .persist(&verified_update())
        .unwrap();
    coordinator
        .journal
        .record_staged_bound(
            "1.2.0",
            &StagedUpdate {
                path: directory.join("staged.update"),
                artifact_sha256: "c".repeat(64),
            },
            metadata_sha256,
        )
        .unwrap();
}

#[test]
fn coordinator_requires_confirmation_and_persists_healthy_install() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    record(&coordinator, directory.path());
    assert_eq!(
        coordinator.prepare_restart(1, false),
        Err(UpdateCoordinatorError::ActiveTaskRuns)
    );
    coordinator
        .trust_journal
        .initialize("1.0.0", "1.0.0")
        .unwrap();
    assert_eq!(
        coordinator.prepare_restart(1, true).unwrap().state,
        UpdateInstallState::RestartRequired
    );
    coordinator.begin_health_check().unwrap();
    assert_eq!(
        coordinator.complete_health(true, "1.2.0").unwrap().state,
        UpdateInstallState::Committed
    );
    assert_eq!(
        coordinator
            .trust_journal
            .read()
            .unwrap()
            .unwrap()
            .installed_version,
        "1.2.0"
    );
}

#[test]
fn coordinator_persists_explicit_rollback_after_failed_health() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    record(&coordinator, directory.path());
    coordinator.prepare_restart(0, false).unwrap();
    coordinator.begin_health_check().unwrap();
    assert_eq!(
        coordinator.complete_health(false, "1.2.0").unwrap().state,
        UpdateInstallState::RolledBack
    );
}

#[test]
fn coordinator_preserves_signed_artifact_suffix_in_staging_path() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    let path = coordinator
        .staged_path(
            "1.2.0",
            &"c".repeat(64),
            "https://updates.example.test/runne_1.2.0.AppImage",
        )
        .unwrap();
    assert!(path.ends_with("runne-1.2.0-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.AppImage"));
}

#[test]
fn coordinator_can_abort_restart_when_native_install_does_not_start() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    record(&coordinator, directory.path());
    coordinator.prepare_restart(0, false).unwrap();
    assert_eq!(
        coordinator.abort_restart().unwrap().state,
        UpdateInstallState::Staged
    );
}
