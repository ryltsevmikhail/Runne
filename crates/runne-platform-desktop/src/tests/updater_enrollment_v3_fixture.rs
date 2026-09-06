use super::super::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleV3,
    NativeEnrollmentTupleV3CodeIdentities, NativeEnrollmentTupleV3Deployment,
    NativeEnrollmentTupleV3Digests, NativeEnrollmentTupleV3ProtocolCompatibility,
    NativeEnrollmentTupleV3ProtocolVersions, UpdateTargetV2,
};
use runne_api::{
    DaemonEnrollmentLaunchPreludeV1, ExecutableIdentityV1, LaunchSecret,
    PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, ProtectedCredentialEnrollmentLaunchBindingV1,
    ProtectedCredentialEnrollmentReadyV3, ProtectedReadyV1, ProtectedRuntimeProfileV1,
    ProviderActivationBindingV1, ProviderActivationReadinessV1, StableRuntimeBindingV1,
};

fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70;
    value[8] = 0x80;
    value
}

fn identity(identifier: &str, cdhash: char) -> MacOsCodeIdentityExpectationV1 {
    MacOsCodeIdentityExpectationV1::new(
        identifier,
        "758F9Z45SR",
        cdhash.to_string().repeat(40),
    )
    .unwrap()
}

pub fn macos_tuple_v3(
    target: &UpdateTargetV2,
    service_digest: char,
) -> NativeEnrollmentTupleV3 {
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

pub fn owned(
    release: [u8; 32],
    qualification: [u8; 32],
) -> runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3 {
    let profile = ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "fixture",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        ExecutableIdentityV1::new([3; 32], [4; 32], 1).unwrap(),
        profile,
        StableRuntimeBindingV1::new(id(10), "owner", id(11), "fixture", [1; 32], [2; 32])
            .unwrap(),
        id(12),
        1,
        id(13),
        "https://127.0.0.1",
        [14; 32],
        vec![15],
        vec!["provider.enroll".into()],
    )
    .unwrap();
    let keys = LaunchSecret::from_bytes([3; 32]).unwrap().derive_keys();
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        id(1), id(2), [10; 32], [11; 32], [12; 32], [21; 32], [22; 32], 1, 10, 20,
    )
    .unwrap();
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [21; 32],
        release,
        qualification,
        [22; 32],
        1,
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
            .enrollment_launch_commitment(&prelude),
    )
    .unwrap();
    ProtectedCredentialEnrollmentReadyV3::new(
        ready,
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding,
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .unwrap()
    .owned_launch()
}
