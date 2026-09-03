use super::super::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentQualification,
    MacOsCodeIdentityExpectationV1, NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleV2,
    NativeEnrollmentTupleV3, NativeEnrollmentTupleV3CodeIdentities,
    NativeEnrollmentTupleV3Deployment, NativeEnrollmentTupleV3Digests,
    NativeEnrollmentTupleV3ProtocolCompatibility, NativeEnrollmentTupleV3ProtocolVersions,
    UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2,
    UpdateTargetV2Binding, UpdateTargetsRoleV2, UpdateTimestampRoleV2, UpdateTrustRootV2,
    UpdateV2VerificationError, verify_update_v2,
};
use ed25519_dalek::{Signer, SigningKey};

const TUPLE_DIGEST: &str = "cc15dcd7b26158e7931a2f7cbc01e3243523800209c81b309e738f8b41ea6a2e";
const BINDING_DIGEST: &str = "2f2e790095684939377ae3e6991bef381ef1bd314f0f33b501c3a6164f228897";
const RELEASE_BINDING_DIGEST: &str =
    "0a0030f450326a725e260adc9a9a81056b1151b9e2e06bca2fa50752f7280781";

#[cfg(target_os = "macos")]
#[path = "updater_enrollment_qualification/credential_service.rs"]
mod credential_service;

fn macos_tuple(target: &UpdateTargetV2) -> NativeEnrollmentTupleV2 {
    NativeEnrollmentTupleV2::new_macos(
        target.release_candidate_sha256.clone(), "c".repeat(64), "e".repeat(64),
        "f".repeat(64), target.bundle_sha256.clone(), "com.runne.desktop", "RUNNE12345",
        "3".repeat(40), "com.runne.writer", "RUNNE12345", "1".repeat(40),
        "com.runne.daemon", "RUNNE12345", "2".repeat(40), target,
    )
    .unwrap()
}

fn artifacts(target: &UpdateTargetV2) -> MeasuredNativeEnrollmentArtifactsV1 {
    MeasuredNativeEnrollmentArtifactsV1::test_only_from_digests(
        "c".repeat(64), "e".repeat(64), "f".repeat(64), target.bundle_sha256.clone(),
    )
    .unwrap()
}

fn qualified_target(expires_at_unix_seconds: u64) -> UpdateTargetV2 {
    let mut target = super::updater_enrollment_macos_identity::target();
    let tuple = macos_tuple(&target);
    let qualification = NativeEnrollmentQualificationRowV1::new(
        &target, &tuple, "9".repeat(64), 99, expires_at_unix_seconds,
    )
    .unwrap();
    target.native_enrollment_tuple = Some(tuple.with_qualification(&target, qualification).unwrap());
    target
}

fn identity(identifier: &str, cdhash: char) -> MacOsCodeIdentityExpectationV1 {
    MacOsCodeIdentityExpectationV1::new(
        identifier,
        "758F9Z45SR",
        cdhash.to_string().repeat(40),
    )
    .unwrap()
}

fn macos_tuple_v3(target: &UpdateTargetV2, service_digest: char) -> NativeEnrollmentTupleV3 {
    NativeEnrollmentTupleV3::new(
        NativeEnrollmentTupleV3Digests {
            candidate_sha256: target.release_candidate_sha256.clone(),
            desktop_sha256: "1".repeat(64),
            writer_sha256: "2".repeat(64),
            daemon_sha256: "3".repeat(64),
            credential_service_sha256: service_digest.to_string().repeat(64),
            launch_agent_plist_sha256: "5".repeat(64),
            entitlements_sha256: "6".repeat(64),
            provisioning_sha256: "7".repeat(64),
            xpc_protocol_sha256: "8".repeat(64),
            contract_sha256: target.bundle_sha256.clone(),
        },
        NativeEnrollmentTupleV3Deployment::exact(NativeEnrollmentTupleV3ProtocolVersions::new(
            vec![NativeEnrollmentTupleV3ProtocolCompatibility::new(1, 1, 2, 1, 2, 3, 3)],
        )),
        NativeEnrollmentTupleV3CodeIdentities::new(
            identity("com.runne.desktop", '1'),
            identity("runne", '2'),
            identity("runned", '3'),
            identity("com.runne.credential-service", '4'),
        ),
        target,
    )
    .unwrap()
}

#[test]
fn qualified_v3_admission_requires_the_exact_remeasured_tuple() {
    let mut target = super::updater_enrollment_macos_identity::target();
    target.native_enrollment_tuple = None;
    let measured = macos_tuple_v3(&target, '4');
    let row = NativeEnrollmentQualificationRowV1::new_v3(
        &target,
        &measured,
        "9".repeat(64),
        99,
        200,
    )
    .unwrap();
    target.native_enrollment_tuple_v3 = Some(
        measured
            .clone()
            .with_qualification(&target, row)
            .unwrap(),
    );
    let verified = super::updater_enrollment_macos_identity::verify_target(&target).unwrap();

    let admission = verified.admit_native_enrollment_v3(&measured).unwrap();
    assert!(matches!(
        admission.qualification(),
        NativeEnrollmentQualification::Qualified(_)
    ));
    assert_eq!(admission.installed_generation(), 8);
    assert!(
        verified
            .admit_native_enrollment_v3(&macos_tuple_v3(&target, 'e'))
            .is_none()
    );
    assert_eq!(
        admission
            .desktop_credential_service_configuration()
            .unwrap()
            .role(),
        runne_macos_xpc::CredentialServiceEndpointRole::Desktop,
    );
    assert_eq!(
        admission
            .runtime_credential_service_configuration()
            .unwrap()
            .role(),
        runne_macos_xpc::CredentialServiceEndpointRole::Runtime,
    );
    assert_eq!(
        admission
            .writer_credential_service_configuration()
            .unwrap()
            .role(),
        runne_macos_xpc::CredentialServiceEndpointRole::Writer,
    );
}

#[test]
fn threshold_verified_macos_tuple_with_exact_signed_qualification_is_qualified() {
    let target = qualified_target(200);
    let verified = super::updater_enrollment_macos_identity::verify_target(&target).unwrap();
    let qualification = verified.qualify_native_enrollment(&artifacts(&target));
    let tuple: [u8; 32] = hex::decode(TUPLE_DIGEST).unwrap().try_into().unwrap();
    let release: [u8; 32] = hex::decode(RELEASE_BINDING_DIGEST)
        .unwrap()
        .try_into()
        .unwrap();
    let binding = hex::decode(BINDING_DIGEST).unwrap().try_into().unwrap();

    assert!(matches!(qualification, NativeEnrollmentQualification::Qualified(_)));
    assert_ne!(tuple, release);
    assert!(qualification.matches_exact(release, binding, 100));
    assert!(verified.admit_native_enrollment(&artifacts(&target)).unwrap()
        .qualification().matches_exact(release, binding, 100));
}

#[test]
fn absent_or_stale_signed_qualification_remains_unqualified() {
    let mut absent = super::updater_enrollment_macos_identity::target();
    absent.native_enrollment_tuple = Some(macos_tuple(&absent));
    let absent_verified = super::updater_enrollment_macos_identity::verify_target(&absent).unwrap();
    assert_eq!(
        absent_verified.qualify_native_enrollment(&artifacts(&absent)),
        NativeEnrollmentQualification::Unqualified
    );

    let stale = qualified_target(100);
    let stale_verified = super::updater_enrollment_macos_identity::verify_target(&stale).unwrap();
    assert_eq!(
        stale_verified.qualify_native_enrollment(&artifacts(&stale)),
        NativeEnrollmentQualification::Unqualified
    );
}

#[test]
fn independently_measured_artifact_substitution_never_qualifies() {
    let target = qualified_target(200);
    let substituted = MeasuredNativeEnrollmentArtifactsV1::test_only_from_digests(
        "8".repeat(64), "e".repeat(64), "f".repeat(64), target.bundle_sha256.clone(),
    )
    .unwrap();
    assert_eq!(
        super::updater_enrollment_macos_identity::verify_target(&target)
            .unwrap()
            .qualify_native_enrollment(&substituted),
        NativeEnrollmentQualification::Unqualified
    );
}

#[test]
fn re_signed_candidate_tuple_platform_or_arch_substitution_is_invalid_metadata() {
    let original = qualified_target(200);
    let qualification = serde_json::to_value(original.native_enrollment_tuple.unwrap())
        .unwrap()["nativeEnrollmentQualification"].clone();
    for (candidate, platform, arch) in [
        ("8".repeat(64), "macos", "arm64"),
        ("d".repeat(64), "macos", "aarch64"),
        ("d".repeat(64), "linux", "x86_64"),
    ] {
        let mut target = super::updater_enrollment_macos_identity::target();
        target.release_candidate_sha256 = candidate;
        target.platform = platform.into();
        target.arch = arch.into();
        let replacement = if platform == "macos" {
            macos_tuple(&target)
        } else {
            NativeEnrollmentTupleV2::new(
                target.release_candidate_sha256.clone(),
                "c".repeat(64),
                "e".repeat(64),
                "f".repeat(64),
                target.bundle_sha256.clone(),
                &target,
            )
            .unwrap()
        };
        let mut tuple = serde_json::to_value(replacement).unwrap();
        tuple["nativeEnrollmentQualification"] = qualification.clone();
        target.native_enrollment_tuple = Some(serde_json::from_value(tuple).unwrap());
        assert_eq!(
            super::updater_enrollment_macos_identity::verify_target(&target),
            Err(UpdateV2VerificationError::InvalidMetadata)
        );
    }

    let mut target = super::updater_enrollment_macos_identity::target();
    let replacement = NativeEnrollmentTupleV2::new_macos(
        target.release_candidate_sha256.clone(),
        "8".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
        target.bundle_sha256.clone(),
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
    let mut tuple = serde_json::to_value(replacement).unwrap();
    tuple["nativeEnrollmentQualification"] = qualification;
    target.native_enrollment_tuple = Some(serde_json::from_value(tuple).unwrap());
    assert_eq!(
        super::updater_enrollment_macos_identity::verify_target(&target),
        Err(UpdateV2VerificationError::InvalidMetadata)
    );
}

#[test]
fn changing_qualification_without_resigning_fails_targets_quorum() {
    let target = qualified_target(200);
    let (mut metadata, trust) = signed_metadata(&target);
    let mut tuple = serde_json::to_value(&metadata.targets.target.native_enrollment_tuple).unwrap();
    tuple["nativeEnrollmentQualification"]["receiptSha256"] = "8".repeat(64).into();
    metadata.targets.target.native_enrollment_tuple = serde_json::from_value(tuple).unwrap();

    assert_eq!(verify(&metadata, &trust, &target), Err(UpdateV2VerificationError::TargetsQuorum));
}

fn signed_metadata(target: &UpdateTargetV2) -> (UpdateMetadataV2, UpdateTrustRootV2) {
    let roots = [SigningKey::from_bytes(&[31; 32]), SigningKey::from_bytes(&[32; 32]), SigningKey::from_bytes(&[33; 32])];
    let timestamp = SigningKey::from_bytes(&[34; 32]);
    let snapshot = SigningKey::from_bytes(&[35; 32]);
    let trust = UpdateTrustRootV2::from_keys(
        [("root-a", roots[0].verifying_key().to_bytes()), ("root-b", roots[1].verifying_key().to_bytes()), ("root-c", roots[2].verifying_key().to_bytes())],
        ("timestamp", timestamp.verifying_key().to_bytes()), ("snapshot", snapshot.verifying_key().to_bytes()),
    );
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 { version: 8, expires_at_unix_seconds: 500, target: target.clone() };
    let snapshot_role = UpdateSnapshotRoleV2 { version: 9, expires_at_unix_seconds: 500, targets_version: 8 };
    let timestamp_role = UpdateTimestampRoleV2 { version: 10, expires_at_unix_seconds: 500, snapshot_version: 9 };
    (UpdateMetadataV2 { schema_version: 2, root: root.clone(), targets: targets.clone(), snapshot: snapshot_role.clone(), timestamp: timestamp_role.clone(), root_signatures: signatures(&roots, &root), targets_signatures: signatures(&roots, &targets), snapshot_signature: signed_role(&snapshot, &snapshot_role), timestamp_signature: signed_role(&timestamp, &timestamp_role) }, trust)
}

fn signatures<T: serde::Serialize>(keys: &[SigningKey; 3], value: &T) -> Vec<UpdateSignatureV2> {
    ["root-a", "root-b"].into_iter().zip(keys).map(|(key_id, key)| UpdateSignatureV2 { key_id: key_id.into(), signature: signed_role(key, value) }).collect()
}

fn signed_role<T: serde::Serialize>(key: &SigningKey, value: &T) -> String {
    hex::encode(key.sign(&serde_json::to_vec(value).unwrap()).to_bytes())
}

fn verify(metadata: &UpdateMetadataV2, trust: &UpdateTrustRootV2, target: &UpdateTargetV2) -> Result<super::super::VerifiedUpdateV2, UpdateV2VerificationError> {
    verify_update_v2(metadata, trust, &UpdateTargetV2Binding { product_id: &target.product_id, platform: &target.platform, arch: &target.arch, min_os: &target.min_os, profile_id: &target.profile_id, bundle_sha256: &target.bundle_sha256, runtime_version: &target.runtime_version, runtime_digest: &target.runtime_digest, channel: &target.channel }, 100, "1.0.0", "1.0.0")
}
