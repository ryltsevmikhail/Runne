use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest as _, Sha256};

use super::super::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentQualification, NativeEnrollmentTupleV1,
    UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2,
    UpdateTargetV2Binding, UpdateTargetsRoleV2, UpdateTimestampRoleV2, UpdateTrustRootV2,
    VerifiedUpdateV2, verify_update_v2,
};

fn target() -> UpdateTargetV2 {
    let mut target = super::updater_enrollment_tuple::target();
    target.platform = "macos".into();
    target.arch = "arm64".into();
    target.min_os = "13.0".into();
    target.artifact_url = "https://updates.example.test/runne.dmg".into();
    target
}

#[test]
fn macos_tuple_requires_exact_non_adhoc_writer_code_identity() {
    let macos = target();
    assert!(
        NativeEnrollmentTupleV1::new(
            macos.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            macos.bundle_sha256.clone(),
            &macos,
        )
        .is_err()
    );
    let valid = || {
        NativeEnrollmentTupleV1::new_macos(
            macos.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            macos.bundle_sha256.clone(),
            "com.runne.writer",
            "RUNNE12345",
            "1".repeat(40),
            "com.runne.daemon",
            "RUNNE12345",
            "2".repeat(40),
            &macos,
        )
    };
    assert!(valid().is_ok());
    assert!(
        NativeEnrollmentTupleV1::new_macos(
            macos.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            macos.bundle_sha256.clone(),
            "com.runne.shared",
            "RUNNE12345",
            "1".repeat(40),
            "com.runne.shared",
            "RUNNE12345",
            "1".repeat(40),
            &macos,
        )
        .is_err()
    );
    for (identifier, team, cdhash) in [
        ("com.runne.*", "RUNNE12345", "1".repeat(40)),
        ("com.runne.writer", "", "1".repeat(40)),
        ("com.runne.writer", "RUNNE12345", "1".repeat(39)),
        ("com.runne.writer", "runne12345", "1".repeat(40)),
    ] {
        assert!(
            NativeEnrollmentTupleV1::new_macos(
                macos.release_candidate_sha256.clone(),
                "e".repeat(64),
                "f".repeat(64),
                macos.bundle_sha256.clone(),
                identifier,
                team,
                cdhash,
                "com.runne.daemon",
                "RUNNE12345",
                "2".repeat(40),
                &macos,
            )
            .is_err()
        );
    }
    let linux = super::updater_enrollment_tuple::target();
    assert!(
        NativeEnrollmentTupleV1::new_macos(
            linux.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            linux.bundle_sha256.clone(),
            "com.runne.writer",
            "RUNNE12345",
            "1".repeat(40),
            "com.runne.daemon",
            "RUNNE12345",
            "2".repeat(40),
            &linux,
        )
        .is_err()
    );
}

#[test]
fn verified_macos_tuple_admission_mints_only_a_tuple_bound_launch() {
    let directory = tempfile::tempdir().unwrap();
    let writer = directory.path().join("runne");
    std::fs::write(&writer, b"measured macos writer").unwrap();
    let writer_digest = hex::encode(Sha256::digest(b"measured macos writer"));
    let mut macos = target();
    macos.native_enrollment_tuple = Some(
        NativeEnrollmentTupleV1::new_macos(
            macos.release_candidate_sha256.clone(),
            writer_digest.clone(),
            "f".repeat(64),
            macos.bundle_sha256.clone(),
            "com.runne.writer",
            "RUNNE12345",
            "1".repeat(40),
            "com.runne.daemon",
            "RUNNE12345",
            "2".repeat(40),
            &macos,
        )
        .unwrap(),
    );
    let verified = verify_target(&macos).unwrap();
    let artifacts = MeasuredNativeEnrollmentArtifactsV1::new(
        macos.artifact_sha256.clone(),
        writer_digest,
        "f".repeat(64),
        macos.bundle_sha256,
    )
    .unwrap();

    assert_eq!(
        verified.qualify_native_enrollment(&artifacts),
        NativeEnrollmentQualification::Unqualified
    );
    let admission = verified.admit_native_enrollment(&artifacts).unwrap();
    assert!(admission.verified_writer(writer.clone()).is_err());
    let launch = admission.verified_macos_writer(writer).unwrap();
    assert!(launch.code_requirement().contains("com.runne.writer"));
    assert!(launch.daemon_code_requirement().contains("com.runne.daemon"));
}

#[test]
fn threshold_signed_macos_tuple_tampering_is_invalid_metadata() {
    let mut macos = target();
    let tuple = NativeEnrollmentTupleV1::new_macos(
        macos.release_candidate_sha256.clone(),
        "e".repeat(64),
        "f".repeat(64),
        macos.bundle_sha256.clone(),
        "com.runne.writer",
        "RUNNE12345",
        "1".repeat(40),
        "com.runne.daemon",
        "RUNNE12345",
        "2".repeat(40),
        &macos,
    )
    .unwrap();
    let original = serde_json::to_value(tuple).unwrap();
    for tampered in [
        tamper(&original, |value| {
            value["writerCodeIdentity"]["cdhash"] = "3".repeat(40).into();
        }),
        tamper(&original, |value| {
            value.as_object_mut().unwrap().remove("daemonCodeIdentity");
        }),
        tamper(&original, |value| {
            value["tupleSha256"] = "0".repeat(64).into();
        }),
    ] {
        macos.native_enrollment_tuple = Some(serde_json::from_value(tampered).unwrap());
        assert_eq!(
            verify_target(&macos),
            Err(super::super::UpdateV2VerificationError::InvalidMetadata)
        );
    }
}

fn tamper(
    original: &serde_json::Value,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> serde_json::Value {
    let mut tampered = original.clone();
    mutate(&mut tampered);
    tampered
}

fn verify_target(
    target: &UpdateTargetV2,
) -> Result<VerifiedUpdateV2, super::super::UpdateV2VerificationError> {
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
        root_signatures: signatures(&roots, &root),
        targets_signatures: signatures(&roots, &targets),
        snapshot_signature: signed_role(&snapshot, &snapshot_role),
        timestamp_signature: signed_role(&timestamp, &timestamp_role),
    };
    let binding = UpdateTargetV2Binding {
        product_id: &target.product_id,
        platform: &target.platform,
        arch: &target.arch,
        min_os: &target.min_os,
        profile_id: &target.profile_id,
        bundle_sha256: &target.bundle_sha256,
        runtime_version: &target.runtime_version,
        runtime_digest: &target.runtime_digest,
        channel: &target.channel,
    };
    verify_update_v2(&metadata, &trust, &binding, 100, "1.0.0", "1.0.0")
}

fn signatures<T: serde::Serialize>(roots: &[SigningKey; 3], role: &T) -> Vec<UpdateSignatureV2> {
    ["root-a", "root-b"]
        .into_iter()
        .zip(roots)
        .map(|(key_id, key)| UpdateSignatureV2 {
            key_id: key_id.into(),
            signature: signed_role(key, role),
        })
        .collect()
}

fn signed_role<T: serde::Serialize>(key: &SigningKey, role: &T) -> String {
    hex::encode(key.sign(&serde_json::to_vec(role).unwrap()).to_bytes())
}
