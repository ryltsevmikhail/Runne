use ed25519_dalek::{Signer, SigningKey};

use sha2::{Digest as _, Sha256};

use crate::{
    NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleV2, UpdateMetadataV2,
    UpdateRootRoleV2, UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2,
    UpdateTargetV2Binding, UpdateTargetsRoleV2, UpdateTimestampRoleV2, UpdateTrustRootV2,
    VerifiedUpdateV2, verify_update_v2,
};

pub(super) struct FixtureSigningMaterial {
    pub(super) trust: UpdateTrustRootV2,
    pub(super) roots: [SigningKey; 3],
    pub(super) timestamp: SigningKey,
    pub(super) snapshot: SigningKey,
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn fixture_signing_material() -> FixtureSigningMaterial {
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
    FixtureSigningMaterial {
        trust,
        roots,
        timestamp,
        snapshot,
    }
}

pub(super) fn fixture_target(
    expires_at: u64,
    now: u64,
    hashes: &[String; 4],
) -> (UpdateTargetV2, [u8; 32]) {
    let mut target = UpdateTargetV2 {
        product_id: "com.runne.desktop".into(),
        version: "1.2.0".into(),
        platform: "macos".into(),
        arch: "arm64".into(),
        artifact_sha256: digest(b"installer"),
        artifact_size: 1,
        artifact_url: "https://updates.example.test/runne.dmg".into(),
        release_candidate_sha256: digest(b"candidate"),
        min_os: "macos-13".into(),
        profile_id: "profile".into(),
        bundle_sha256: hashes[3].clone(),
        runtime_version: "0.1.0".into(),
        runtime_digest: hashes[2].clone(),
        channel: "stable".into(),
        published_at_unix_seconds: now.saturating_sub(5),
        expires_at_unix_seconds: expires_at,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
        qualification_bootstrap_client_v1: None,
    };
    let tuple = NativeEnrollmentTupleV2::new_macos(
        target.release_candidate_sha256.clone(),
        hashes[0].clone(),
        hashes[1].clone(),
        hashes[2].clone(),
        hashes[3].clone(),
        "com.runne.desktop",
        "RUNNE12345",
        "3".repeat(40),
        "com.runne.writer",
        "RUNNE12345",
        "1".repeat(40),
        "com.runne.daemon",
        "RUNNE12345",
        "2".repeat(40),
        &target,
    )
    .unwrap();
    let qualification = NativeEnrollmentQualificationRowV1::new(
        &target,
        &tuple,
        digest(b"fixture-only-qualification"),
        now.saturating_sub(1),
        expires_at,
    )
    .unwrap();
    target.native_enrollment_tuple =
        Some(tuple.with_qualification(&target, qualification).unwrap());
    let encoded = serde_json::to_value(&target.native_enrollment_tuple).unwrap();
    let qualification = hex::decode(
        encoded["nativeEnrollmentQualification"]["bindingSha256"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    (target, qualification)
}

pub(super) fn fixture_verified_update(
    target: UpdateTargetV2,
    expires_at: u64,
    now: u64,
    hashes: &[String; 4],
    signing: &FixtureSigningMaterial,
) -> (VerifiedUpdateV2, [u8; 32]) {
    let root = UpdateRootRoleV2::from_trust(&signing.trust, 7);
    let targets = UpdateTargetsRoleV2 {
        version: 8,
        expires_at_unix_seconds: expires_at,
        target,
    };
    let snapshot_role = UpdateSnapshotRoleV2 {
        version: 9,
        expires_at_unix_seconds: expires_at,
        targets_version: 8,
    };
    let timestamp_role = UpdateTimestampRoleV2 {
        version: 10,
        expires_at_unix_seconds: expires_at,
        snapshot_version: 9,
    };
    let metadata = UpdateMetadataV2 {
        schema_version: 2,
        root: root.clone(),
        targets: targets.clone(),
        snapshot: snapshot_role.clone(),
        timestamp: timestamp_role.clone(),
        root_signatures: signatures(&signing.roots, &root),
        targets_signatures: signatures(&signing.roots, &targets),
        snapshot_signature: signed(&signing.snapshot, &snapshot_role),
        timestamp_signature: signed(&signing.timestamp, &timestamp_role),
    };
    let binding = UpdateTargetV2Binding {
        product_id: "com.runne.desktop",
        platform: "macos",
        arch: "arm64",
        min_os: "macos-13",
        profile_id: "profile",
        bundle_sha256: &hashes[3],
        runtime_version: "0.1.0",
        runtime_digest: &hashes[2],
        channel: "stable",
    };
    let verified =
        verify_update_v2(&metadata, &signing.trust, &binding, now, "1.2.0", "1.0.0").unwrap();
    let release = runne_api::verify_signed_update_metadata_v2(&metadata, &signing.trust, now)
        .unwrap()
        .qualified_release_candidate()
        .unwrap()
        .release_binding_digest();
    (verified, release)
}

fn signatures<T: serde::Serialize>(keys: &[SigningKey; 3], value: &T) -> Vec<UpdateSignatureV2> {
    ["root-a", "root-b"]
        .into_iter()
        .zip(keys)
        .map(|(key_id, key)| UpdateSignatureV2 {
            key_id: key_id.into(),
            signature: signed(key, value),
        })
        .collect()
}

fn signed<T: serde::Serialize>(key: &SigningKey, value: &T) -> String {
    hex::encode(key.sign(&serde_json::to_vec(value).unwrap()).to_bytes())
}
