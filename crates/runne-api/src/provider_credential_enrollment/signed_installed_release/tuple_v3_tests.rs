use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use super::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleV3, NativeEnrollmentTupleV3CodeIdentities,
    NativeEnrollmentTupleV3Deployment, NativeEnrollmentTupleV3Digests,
    NativeEnrollmentTupleV3ProtocolCompatibility, NativeEnrollmentTupleV3ProtocolVersions,
    UpdateTargetV2,
};

fn hash(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn target() -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: "com.runne.desktop".into(),
        version: "1.2.3".into(),
        platform: "macos".into(),
        arch: "arm64".into(),
        artifact_sha256: hash('a'),
        artifact_size: 10,
        artifact_url: "https://updates.example.test/Runne.dmg".into(),
        release_candidate_sha256: hash('0'),
        min_os: "13.0".into(),
        profile_id: "gocode-ui-client/2".into(),
        bundle_sha256: hash('9'),
        runtime_version: "0.1.0".into(),
        runtime_digest: hash('b'),
        channel: "stable".into(),
        published_at_unix_seconds: 100,
        expires_at_unix_seconds: 500,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
    }
}

fn identity(identifier: &str, cdhash: char) -> MacOsCodeIdentityExpectationV1 {
    MacOsCodeIdentityExpectationV1::new(identifier, "758F9Z45SR", cdhash.to_string().repeat(40))
        .unwrap()
}

fn tuple(target: &UpdateTargetV2) -> NativeEnrollmentTupleV3 {
    NativeEnrollmentTupleV3::new(
        NativeEnrollmentTupleV3Digests {
            candidate_sha256: target.release_candidate_sha256.clone(),
            desktop_sha256: hash('1'),
            writer_sha256: hash('2'),
            daemon_sha256: hash('3'),
            credential_service_sha256: hash('4'),
            launch_agent_plist_sha256: hash('5'),
            entitlements_sha256: hash('6'),
            provisioning_sha256: hash('7'),
            xpc_protocol_sha256: hash('8'),
            contract_sha256: target.bundle_sha256.clone(),
        },
        NativeEnrollmentTupleV3Deployment::exact(NativeEnrollmentTupleV3ProtocolVersions::new(
            vec![NativeEnrollmentTupleV3ProtocolCompatibility::new(
                1, 1, 2, 1, 2, 3, 3,
            )],
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
fn signed_v3_metadata_verifies_and_exposes_exact_matchers() {
    let (mut metadata, trust, _) = super::tests::pinned_test_facts();
    metadata.targets.target.native_enrollment_tuple = None;
    let tuple = tuple(&metadata.targets.target);
    let expected = serde_json::to_value(&tuple).unwrap();
    metadata.targets.target.native_enrollment_tuple_v3 = Some(tuple);
    resign_targets(&mut metadata);

    let verified = super::verify_signed_update_metadata_v2(&metadata, &trust, 100).unwrap();
    let verified = verified.native_enrollment_tuple_v3().unwrap();
    let digests: NativeEnrollmentTupleV3Digests =
        serde_json::from_value(expected["digests"].clone()).unwrap();
    assert!(verified.matches_release_digests(&digests));
    assert!(verified.matches_credential_service_identity(
        "com.runne.credential-service",
        "758F9Z45SR",
        &"4".repeat(40),
    ));
    for (matches, identifier, cdhash) in [
        (
            verified.matches_desktop_identity("com.runne.desktop", "758F9Z45SR", &"1".repeat(40)),
            "com.runne.desktop",
            '1',
        ),
        (
            verified.matches_writer_identity("runne", "758F9Z45SR", &"2".repeat(40)),
            "runne",
            '2',
        ),
        (
            verified.matches_daemon_identity("runned", "758F9Z45SR", &"3".repeat(40)),
            "runned",
            '3',
        ),
    ] {
        assert!(matches, "{identifier} {cdhash}");
    }
    assert!(!verified.matches_writer_identity("runned", "758F9Z45SR", &"3".repeat(40)));
    assert_eq!(
        verified.service_application_id_group(),
        "758F9Z45SR.com.runne.credential-service"
    );
    assert_eq!(
        verified
            .protocol_compatibility_bundles()
            .collect::<Vec<_>>(),
        vec![NativeEnrollmentTupleV3ProtocolCompatibility::new(
            1, 1, 2, 1, 2, 3, 3,
        )]
    );

    metadata.targets.target.native_enrollment_tuple = super::tests::pinned_test_facts()
        .0
        .targets
        .target
        .native_enrollment_tuple;
    resign_targets(&mut metadata);
    assert_eq!(
        super::verify_signed_update_metadata_v2(&metadata, &trust, 100),
        Err(super::SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)
    );
}

#[test]
fn v2_canonical_metadata_fixture_remains_byte_exact() {
    let bytes = include_bytes!("../../../tests/fixtures/signed_installed_release_v2.json");
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        "721c18fee5369ff2c3e8c95342e73d10df0db33b3512281bf71997deaec45fb6"
    );
    let decoded: super::UpdateMetadataV2 = serde_json::from_slice(bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
}

#[test]
fn tuple_v3_binds_every_digest_deployment_and_identity_field() {
    let target = target();
    let baseline = tuple(&target);
    assert!(baseline.valid_signed(&target));
    let value = serde_json::to_value(&baseline).unwrap();
    assert_eq!(
        value["tupleSha256"],
        "ba868ecb64f649067b062c43f4f783041f47cae90d85b8585f77f494632f73dd"
    );

    for field in [
        "candidateSha256",
        "desktopSha256",
        "writerSha256",
        "daemonSha256",
        "credentialServiceSha256",
        "launchAgentPlistSha256",
        "entitlementsSha256",
        "provisioningSha256",
        "xpcProtocolSha256",
        "contractSha256",
    ] {
        let mut changed = value.clone();
        changed["digests"][field] = hash('a').into();
        assert!(!decode(changed).valid_signed(&target), "digest {field}");
    }
    for field in [
        "helperBundleIdentifier",
        "serviceApplicationIdGroup",
        "desktopMachService",
        "runtimeMachService",
        "writerMachService",
        "xpcTransport",
    ] {
        let mut changed = value.clone();
        changed["deployment"][field] = "changed".into();
        assert!(!decode(changed).valid_signed(&target), "deployment {field}");
    }
    for field in [
        "registrationWire",
        "registrationAuthSuite",
        "providerFrameWire",
        "providerGrantAuth",
        "runtimeEnvelopeWire",
        "runtimeRequestAuth",
        "runtimeReplyAuth",
    ] {
        let mut versions = value.clone();
        versions["deployment"]["xpcProtocolVersions"]["compatibilityBundles"][0][field] =
            serde_json::json!(0);
        assert!(!decode(versions).valid_signed(&target), "protocol {field}");
    }
    let mut duplicate = value.clone();
    let bundle = duplicate["deployment"]["xpcProtocolVersions"]["compatibilityBundles"][0].clone();
    duplicate["deployment"]["xpcProtocolVersions"]["compatibilityBundles"] =
        serde_json::json!([bundle.clone(), bundle]);
    assert!(!decode(duplicate).valid_signed(&target));

    for role in ["desktop", "writer", "daemon", "credentialService"] {
        for (field, replacement) in [
            ("identifier", "bad!"),
            ("teamIdentifier", "BAD"),
            ("cdhash", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        ] {
            let mut changed = value.clone();
            changed["codeIdentities"][role][field] = replacement.into();
            assert!(!decode(changed).valid_signed(&target), "{role}.{field}");
        }
    }
}

#[test]
fn tuple_v3_rejects_missing_unknown_duplicate_mixed_and_wrong_version() {
    let mut target = target();
    let tuple = tuple(&target);
    let mut value = serde_json::to_value(&tuple).unwrap();
    value.as_object_mut().unwrap().remove("digests");
    assert!(serde_json::from_value::<NativeEnrollmentTupleV3>(value).is_err());

    let mut unknown = serde_json::to_value(&tuple).unwrap();
    unknown["unknown"] = true.into();
    assert!(serde_json::from_value::<NativeEnrollmentTupleV3>(unknown).is_err());

    let mut version = serde_json::to_value(&tuple).unwrap();
    version["schemaVersion"] = 4.into();
    assert!(!decode(version).valid_signed(&target));

    target.native_enrollment_tuple_v3 = Some(tuple);
    let encoded = serde_json::to_string(&target).unwrap();
    let duplicate = encoded.replacen(
        "\"nativeEnrollmentTupleV3\":",
        "\"nativeEnrollmentTupleV3\":null,\"nativeEnrollmentTupleV3\":",
        1,
    );
    assert!(serde_json::from_str::<UpdateTargetV2>(&duplicate).is_err());

    let fixture: super::UpdateMetadataV2 = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/signed_installed_release_v2.json"
    ))
    .unwrap();
    target.native_enrollment_tuple = fixture.targets.target.native_enrollment_tuple;
    assert!(!target.native_enrollment_tuples_valid());
}

fn decode(value: serde_json::Value) -> NativeEnrollmentTupleV3 {
    serde_json::from_value(value).unwrap()
}

fn resign_targets(metadata: &mut super::UpdateMetadataV2) {
    metadata.targets_signatures = [31_u8, 32]
        .into_iter()
        .zip(["root-a", "root-b"])
        .map(|(byte, key_id)| {
            let key = SigningKey::from_bytes(&[byte; 32]);
            super::UpdateSignatureV2 {
                key_id: key_id.into(),
                signature: hex::encode(
                    key.sign(&serde_json::to_vec(&metadata.targets).unwrap())
                        .to_bytes(),
                ),
            }
        })
        .collect();
}
