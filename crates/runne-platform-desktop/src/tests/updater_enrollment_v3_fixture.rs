use super::super::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleV3,
    NativeEnrollmentTupleV3CodeIdentities, NativeEnrollmentTupleV3Deployment,
    NativeEnrollmentTupleV3Digests, NativeEnrollmentTupleV3ProtocolCompatibility,
    NativeEnrollmentTupleV3ProtocolVersions, UpdateTargetV2,
};

fn identity(identifier: &str, cdhash: char) -> MacOsCodeIdentityExpectationV1 {
    MacOsCodeIdentityExpectationV1::new(
        identifier,
        "758F9Z45SR",
        cdhash.to_string().repeat(40),
    )
    .unwrap()
}

pub(super) fn macos_tuple_v3(
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
