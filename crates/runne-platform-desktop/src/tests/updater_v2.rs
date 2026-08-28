use ed25519_dalek::{Signer, SigningKey};

use super::super::*;

fn signed_role<T: serde::Serialize>(key: &SigningKey, role: &T) -> String {
    hex::encode(key.sign(&serde_json::to_vec(role).unwrap()).to_bytes())
}

#[test]
#[allow(clippy::too_many_lines)]
fn v2_update_requires_two_root_and_two_targets_signatures() {
    let roots = [
        SigningKey::from_bytes(&[21; 32]),
        SigningKey::from_bytes(&[22; 32]),
        SigningKey::from_bytes(&[23; 32]),
    ];
    let timestamp = SigningKey::from_bytes(&[24; 32]);
    let snapshot = SigningKey::from_bytes(&[25; 32]);
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
        version: "1.2.3".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        artifact_sha256: "a".repeat(64),
        artifact_size: 10,
        artifact_url: "https://updates.example.test/runne.AppImage".into(),
        release_candidate_sha256: "d".repeat(64),
        min_os: "ubuntu-22.04".into(),
        profile_id: "gocode-ui-client/2".into(),
        bundle_sha256: "b".repeat(64),
        runtime_version: "0.1.0".into(),
        runtime_digest: "c".repeat(64),
        channel: "stable".into(),
        published_at_unix_seconds: 100,
        expires_at_unix_seconds: 500,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None,
    };
    target.native_enrollment_tuple = Some(
        NativeEnrollmentTupleV1::new(
            target.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            target.bundle_sha256.clone(),
            &target,
        )
        .unwrap(),
    );
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 {
        version: 8,
        expires_at_unix_seconds: 500,
        target: target.clone(),
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
        root_signatures: vec![
            UpdateSignatureV2 {
                key_id: "root-a".into(),
                signature: signed_role(&roots[0], &root),
            },
            UpdateSignatureV2 {
                key_id: "root-b".into(),
                signature: signed_role(&roots[1], &root),
            },
        ],
        targets_signatures: vec![
            UpdateSignatureV2 {
                key_id: "root-a".into(),
                signature: signed_role(&roots[0], &targets),
            },
            UpdateSignatureV2 {
                key_id: "root-b".into(),
                signature: signed_role(&roots[1], &targets),
            },
        ],
        snapshot_signature: signed_role(&snapshot, &snapshot_role),
        timestamp_signature: signed_role(&timestamp, &timestamp_role),
    };
    let binding = UpdateTargetV2Binding {
        product_id: "com.runne.desktop",
        platform: "linux",
        arch: "x86_64",
        min_os: "ubuntu-22.04",
        profile_id: "gocode-ui-client/2",
        bundle_sha256: &target.bundle_sha256,
        runtime_version: "0.1.0",
        runtime_digest: &target.runtime_digest,
        channel: "stable",
    };
    let verified = verify_update_v2(&metadata, &trust, &binding, 100, "1.0.0", "1.0.0").unwrap();
    assert_eq!(verified.target().version, "1.2.3");
    assert!(verified.native_enrollment_tuple().is_some());
    let measured = MeasuredNativeEnrollmentArtifactsV1::new(
        target.artifact_sha256.clone(),
        "e".repeat(64),
        "f".repeat(64),
        target.bundle_sha256.clone(),
    )
    .unwrap();
    assert!(matches!(
        verified.qualify_native_enrollment(&measured),
        NativeEnrollmentQualification::Qualified(_)
    ));
    assert_eq!(
        verify_update_v2(&metadata, &trust, &binding, 600, "1.0.0", "1.0.0"),
        Err(UpdateV2VerificationError::Expired)
    );
    assert_eq!(
        verify_update_v2(&metadata, &trust, &binding, 100, "2.0.0", "1.0.0"),
        Err(UpdateV2VerificationError::Rollback)
    );
    let mut mixed = metadata.clone();
    mixed.snapshot.targets_version = 99;
    assert_eq!(
        verify_update_v2(&mixed, &trust, &binding, 100, "1.0.0", "1.0.0"),
        Err(UpdateV2VerificationError::InvalidMetadata)
    );
    let mut candidate_mismatch = metadata.clone();
    candidate_mismatch.targets.target.release_candidate_sha256 = "c".repeat(64);
    candidate_mismatch.targets_signatures = vec![
        UpdateSignatureV2 {
            key_id: "root-a".into(),
            signature: signed_role(&roots[0], &candidate_mismatch.targets),
        },
        UpdateSignatureV2 {
            key_id: "root-b".into(),
            signature: signed_role(&roots[1], &candidate_mismatch.targets),
        },
    ];
    assert_eq!(
        verify_update_v2(&candidate_mismatch, &trust, &binding, 100, "1.0.0", "1.0.0"),
        Err(UpdateV2VerificationError::InvalidMetadata)
    );
    let mut insufficient = metadata;
    insufficient.targets_signatures.pop();
    assert_eq!(
        verify_update_v2(&insufficient, &trust, &binding, 100, "1.0.0", "1.0.0"),
        Err(UpdateV2VerificationError::TargetsQuorum)
    );
}
