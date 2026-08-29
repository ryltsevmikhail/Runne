use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn native_fixture(
    directory: &Path,
    expires_at: u64,
    candidate: String,
) -> (UpdateCoordinator, MeasuredNativeEnrollmentArtifactsV1, VerifiedUpdateV2) {
    let files = ["desktop", "writer", "daemon", "contract"]
        .map(|name| directory.join(name));
    let bytes = [b"desktop".as_slice(), b"writer".as_slice(), b"daemon".as_slice(), b"contract".as_slice()];
    for (path, bytes) in files.iter().zip(bytes) {
        std::fs::write(path, bytes).unwrap();
    }
    let hashes = files.each_ref().map(|path| digest(&std::fs::read(path).unwrap()));
    let installer_hash = digest(b"installer");
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
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut target = UpdateTargetV2 {
        product_id: "com.runne.desktop".into(), version: "1.2.0".into(), platform: "linux".into(), arch: "x86_64".into(),
        artifact_sha256: installer_hash.clone(), artifact_size: 10, artifact_url: "https://updates.example.test/runne.AppImage".into(),
        release_candidate_sha256: candidate, min_os: "ubuntu-22.04".into(), profile_id: "profile".into(), bundle_sha256: hashes[3].clone(),
        runtime_version: "0.1.0".into(), runtime_digest: "b".repeat(64), channel: "stable".into(),
        published_at_unix_seconds: now.saturating_sub(5), expires_at_unix_seconds: expires_at, rollback_floor: "1.0.0".into(), native_enrollment_tuple: None,
    };
    target.native_enrollment_tuple = Some(NativeEnrollmentTupleV1::new(
        target.release_candidate_sha256.clone(), hashes[0].clone(), hashes[1].clone(), hashes[2].clone(), hashes[3].clone(), &target,
    ).unwrap());
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 { version: 8, expires_at_unix_seconds: expires_at, target };
    let snapshot_role = UpdateSnapshotRoleV2 { version: 9, expires_at_unix_seconds: expires_at, targets_version: 8 };
    let timestamp_role = UpdateTimestampRoleV2 { version: 10, expires_at_unix_seconds: expires_at, snapshot_version: 9 };
    let metadata = UpdateMetadataV2 {
        schema_version: 2, root: root.clone(), targets: targets.clone(), snapshot: snapshot_role.clone(), timestamp: timestamp_role.clone(),
        root_signatures: roots[..2].iter().enumerate().map(|(index, key)| UpdateSignatureV2 { key_id: ["root-a", "root-b"][index].into(), signature: signed_role(key, &root) }).collect(),
        targets_signatures: roots[..2].iter().enumerate().map(|(index, key)| UpdateSignatureV2 { key_id: ["root-a", "root-b"][index].into(), signature: signed_role(key, &targets) }).collect(),
        snapshot_signature: signed_role(&snapshot, &snapshot_role), timestamp_signature: signed_role(&timestamp, &timestamp_role),
    };
    let binding = UpdateTargetV2Binding { product_id: "com.runne.desktop", platform: "linux", arch: "x86_64", min_os: "ubuntu-22.04", profile_id: "profile", bundle_sha256: &hashes[3], runtime_version: "0.1.0", runtime_digest: &"b".repeat(64), channel: "stable" };
    let verified_at = expires_at.min(now).saturating_sub(1);
    let verified = verify_update_v2(&metadata, &trust, &binding, verified_at, "1.0.0", "1.0.0").unwrap();
    let coordinator = UpdateCoordinator::new(trust, UpdateTargetBindingConfig { product_id: "com.runne.desktop".into(), platform: "linux".into(), arch: "x86_64".into(), min_os: "ubuntu-22.04".into(), profile_id: "profile".into(), bundle_sha256: hashes[3].clone(), runtime_version: "0.1.0".into(), runtime_digest: "b".repeat(64), channel: "stable".into() }, directory).unwrap();
    let binding = coordinator.installed_metadata.persist(&verified).unwrap();
    coordinator.journal.record_staged_bound("1.2.0", &StagedUpdate { path: directory.join("staged.update"), artifact_sha256: installer_hash }, binding).unwrap();
    coordinator.trust_journal.initialize("1.0.0", "1.0.0").unwrap();
    coordinator.prepare_restart(0, false).unwrap(); coordinator.begin_health_check().unwrap(); coordinator.complete_health(true, "1.2.0").unwrap();
    (
        coordinator,
        MeasuredNativeEnrollmentArtifactsV1::new(
            hashes[0].clone(), hashes[1].clone(), hashes[2].clone(), hashes[3].clone(),
        ).unwrap(),
        verified,
    )
}

#[test]
fn test_admission_rejects_measured_substitution_and_expiry() {
    let directory = tempfile::tempdir().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let (coordinator, artifacts, _) = native_fixture(directory.path(), now + 60, "f".repeat(64));
    assert!(coordinator.admit_installed_native_enrollment_at(now, &artifacts).unwrap().is_some());
    let substituted = MeasuredNativeEnrollmentArtifactsV1::new(
        digest(b"other desktop"), digest(b"writer"), digest(b"daemon"), digest(b"contract"),
    ).unwrap();
    assert!(coordinator.admit_installed_native_enrollment_at(now, &substituted).unwrap().is_none());
    let directory = tempfile::tempdir().unwrap();
    let (coordinator, artifacts, _) = native_fixture(directory.path(), now.saturating_sub(1), "f".repeat(64));
    assert!(coordinator.admit_installed_native_enrollment_at(now, &artifacts).is_err());
}

#[test]
fn transaction_rejects_a_different_signed_candidate_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let (coordinator, artifacts, verified) = native_fixture(directory.path(), now + 60, "f".repeat(64));
    let mut metadata = verified.metadata().clone();
    metadata.targets.target.release_candidate_sha256 = "e".repeat(64);
    metadata.targets.target.native_enrollment_tuple = Some(
        NativeEnrollmentTupleV1::new(
            metadata.targets.target.release_candidate_sha256.clone(),
            digest(b"desktop"),
            digest(b"writer"),
            digest(b"daemon"),
            digest(b"contract"),
            &metadata.targets.target,
        )
        .unwrap(),
    );
    let roots = [SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
    metadata.targets_signatures = roots
        .iter()
        .enumerate()
        .map(|(index, key)| UpdateSignatureV2 {
            key_id: ["root-a", "root-b"][index].into(),
            signature: signed_role(key, &metadata.targets),
        })
        .collect();
    let bundle = digest(b"contract");
    let runtime = "b".repeat(64);
    let replacement = verify_update_v2(
        &metadata,
        &coordinator.trust,
        &UpdateTargetV2Binding {
            product_id: "com.runne.desktop",
            platform: "linux",
            arch: "x86_64",
            min_os: "ubuntu-22.04",
            profile_id: "profile",
            bundle_sha256: &bundle,
            runtime_version: "0.1.0",
            runtime_digest: &runtime,
            channel: "stable",
        },
        now,
        "1.2.0",
        "1.0.0",
    )
    .unwrap();
    coordinator.installed_metadata.persist(&replacement).unwrap();
    assert!(coordinator.admit_installed_native_enrollment_at(now, &artifacts).unwrap().is_none());
}

#[test]
fn legacy_unbound_transaction_requires_explicit_native_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let (coordinator, _, _) = native_fixture(directory.path(), now + 60, "f".repeat(64));
    coordinator.journal.clear().unwrap();
    std::fs::write(
        directory.path().join("updates/install-state.json"),
        format!(
            r#"{{"schemaVersion":1,"state":"staged","version":"1.2.0","artifactSha256":"{}","stagedPath":"{}"}}"#,
            digest(b"desktop"),
            directory.path().join("staged.update").display(),
        ),
    )
    .unwrap();
    assert!(coordinator.prepare_restart(0, false).is_err());
    assert!(coordinator.discard_unbound_legacy_update().unwrap());
    assert_eq!(coordinator.current().unwrap(), None);
    coordinator
        .journal
        .record_staged_bound(
            "1.2.0",
            &StagedUpdate {
                path: directory.path().join("staged.update"),
                artifact_sha256: digest(b"desktop"),
            },
            "b".repeat(64),
        )
        .unwrap();
    assert!(!coordinator.current().unwrap().unwrap().legacy_unbound);
}

#[test]
fn orphan_metadata_temp_allocates_a_new_sequence() {
    let directory = tempfile::tempdir().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let (coordinator, _, verified) = native_fixture(directory.path(), now + 60, "f".repeat(64));
    let temporary = directory
        .path()
        .join("updates/installed-metadata.json.2.tmp");
    std::fs::write(temporary, b"partial").unwrap();
    coordinator.installed_metadata.persist(&verified).unwrap();
    assert!(directory
        .path()
        .join("updates/installed-metadata.json.3.json")
        .exists());
}
