use ed25519_dalek::{Signer as _, SigningKey};
use runne_api::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleV3,
    NativeEnrollmentTupleV3CodeIdentities, NativeEnrollmentTupleV3Deployment,
    NativeEnrollmentTupleV3Digests, NativeEnrollmentTupleV3ProtocolCompatibility,
    NativeEnrollmentTupleV3ProtocolVersions, UpdateMetadataV2, UpdateSignatureV2,
    UpdateTrustRootV2, VerifiedSignedInstalledReleaseV2, verify_exact_signed_installed_release_v2,
    verify_signed_update_metadata_v2,
};

pub(super) fn verified_release() -> VerifiedSignedInstalledReleaseV2 {
    let mut metadata: UpdateMetadataV2 = serde_json::from_slice(include_bytes!(
        "../../../../../../../runne-api/tests/fixtures/signed_installed_release_v2.json"
    ))
    .unwrap();
    let target = &mut metadata.targets.target;
    target.native_enrollment_tuple = None;
    target.release_candidate_sha256 = digest('c');
    target.bundle_sha256 = digest('9');
    let tuple = NativeEnrollmentTupleV3::new(
        NativeEnrollmentTupleV3Digests {
            candidate_sha256: digest('c'),
            desktop_sha256: digest('1'),
            writer_sha256: digest('2'),
            daemon_sha256: digest('3'),
            credential_service_sha256: digest('4'),
            launch_agent_plist_sha256: digest('5'),
            entitlements_sha256: digest('6'),
            provisioning_sha256: digest('7'),
            xpc_protocol_sha256: digest('8'),
            contract_sha256: digest('9'),
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
    .unwrap();
    let qualification =
        NativeEnrollmentQualificationRowV1::new_v3(target, &tuple, digest('a'), 90, 200).unwrap();
    target.native_enrollment_tuple_v3 =
        Some(tuple.with_qualification(target, qualification).unwrap());
    metadata.targets_signatures = [31_u8, 32]
        .into_iter()
        .zip(["root-a", "root-b"])
        .map(|(byte, key_id)| {
            let key = SigningKey::from_bytes(&[byte; 32]);
            UpdateSignatureV2 {
                key_id: key_id.into(),
                signature: hex::encode(
                    key.sign(&serde_json::to_vec(&metadata.targets).unwrap())
                        .to_bytes(),
                ),
            }
        })
        .collect();
    let trust = trust();
    let verified = verify_signed_update_metadata_v2(&metadata, &trust, 100).unwrap();
    verify_exact_signed_installed_release_v2(
        &serde_json::to_vec(&metadata).unwrap(),
        &trust,
        verified
            .qualified_release_candidate_v3()
            .unwrap()
            .release_binding_digest(),
        100,
    )
    .unwrap()
}

fn identity(identifier: &str, cdhash: char) -> MacOsCodeIdentityExpectationV1 {
    MacOsCodeIdentityExpectationV1::new(identifier, "758F9Z45SR", cdhash.to_string().repeat(40))
        .unwrap()
}

fn digest(value: char) -> String {
    value.to_string().repeat(64)
}

fn trust() -> UpdateTrustRootV2 {
    let roots = [31_u8, 32, 33].map(|byte| SigningKey::from_bytes(&[byte; 32]));
    UpdateTrustRootV2::from_keys(
        [
            ("root-a", roots[0].verifying_key().to_bytes()),
            ("root-b", roots[1].verifying_key().to_bytes()),
            ("root-c", roots[2].verifying_key().to_bytes()),
        ],
        (
            "timestamp",
            hex_32("a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"),
        ),
        (
            "snapshot",
            hex_32("74f85cda34d1c27c4621484731e91579c3d9c6cfc0d94b281aa11e9162058aa9"),
        ),
    )
}

fn hex_32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}
