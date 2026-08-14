use gocode_api::{
    ApiPrincipalId, DaemonInstanceId, LocalSessionContractError, RuntimeSessionBinding,
    StableRuntimeBinding,
};
use gocode_domain::event::Sensitivity;
use gocode_domain::id::EventLogLineageId;
const UUID_V7_INSTANCE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const UUID_V7_LINEAGE: &str = "018f2e3a-7000-7000-8000-000000000002";
const SESSION_ID: [u8; 16] = [7; 16];
const CERTIFICATE_SHA256: [u8; 32] = [8; 32];
fn stable_binding() -> StableRuntimeBinding {
    StableRuntimeBinding::new(
        UUID_V7_INSTANCE,
        ApiPrincipalId::new("local-owner").unwrap(),
        UUID_V7_LINEAGE.parse::<EventLogLineageId>().unwrap(),
        "local-default",
        [3; 32],
        [4; 32],
    )
    .unwrap()
}
#[test]
fn session_binding_rejects_zero_launch_generation() {
    let error = RuntimeSessionBinding::new(
        stable_binding(),
        DaemonInstanceId::from_bytes(UUID_V7_INSTANCE),
        0,
        SESSION_ID,
        7,
        Sensitivity::Internal,
        CERTIFICATE_SHA256,
    )
    .expect_err("zero launch generation must fail");
    assert_eq!(error, LocalSessionContractError::InvalidLaunchGeneration);
}

#[test]
fn stable_binding_rejects_empty_profile_and_capability_digest() {
    let principal = ApiPrincipalId::new("local-owner").unwrap();
    let lineage = UUID_V7_LINEAGE.parse::<EventLogLineageId>().unwrap();

    assert_eq!(
        StableRuntimeBinding::new(
            UUID_V7_INSTANCE,
            principal.clone(),
            lineage,
            "",
            [3; 32],
            [4; 32],
        ),
        Err(LocalSessionContractError::EmptyProfileId)
    );
    assert_eq!(
        StableRuntimeBinding::new(
            UUID_V7_INSTANCE,
            principal,
            lineage,
            "local-default",
            [3; 32],
            [0; 32],
        ),
        Err(LocalSessionContractError::EmptyCapabilityDigest)
    );
}

#[test]
fn daemon_instance_identity_requires_a_uuid_v7() {
    let error = "018f2e3a-7000-4000-8000-000000000001"
        .parse::<DaemonInstanceId>()
        .expect_err("a v4 identity must not bind a daemon instance");
    assert_eq!(
        error,
        gocode_domain::id::InvalidIdReason::InvalidUuidVersion {
            expected: 7,
            actual: 4,
        }
    );
}

#[test]
fn stable_binding_rejects_malformed_raw_lineage_identity() {
    let error = StableRuntimeBinding::new(
        UUID_V7_INSTANCE,
        ApiPrincipalId::new("local-owner").unwrap(),
        EventLogLineageId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]),
        "local-default",
        [3; 32],
        [4; 32],
    )
    .expect_err("a raw v4 lineage must not bind a local runtime");
    assert_eq!(
        error,
        LocalSessionContractError::InvalidLineageId(
            gocode_domain::id::InvalidIdReason::InvalidUuidVersion {
                expected: 7,
                actual: 4,
            }
        )
    );
}

#[test]
fn session_binding_requires_separate_session_and_certificate_identities() {
    let daemon = DaemonInstanceId::from_bytes(UUID_V7_INSTANCE);
    assert_eq!(
        RuntimeSessionBinding::new(
            stable_binding(),
            daemon,
            1,
            UUID_V7_INSTANCE,
            7,
            Sensitivity::Internal,
            CERTIFICATE_SHA256,
        ),
        Err(LocalSessionContractError::SessionIdMatchesDaemonInstance)
    );
    assert_eq!(
        RuntimeSessionBinding::new(
            stable_binding(),
            daemon,
            1,
            SESSION_ID,
            7,
            Sensitivity::Internal,
            [0; 32],
        ),
        Err(LocalSessionContractError::EmptyCertificateSha256)
    );

    let binding = RuntimeSessionBinding::new(
        stable_binding(),
        daemon,
        1,
        SESSION_ID,
        7,
        Sensitivity::Internal,
        CERTIFICATE_SHA256,
    )
    .expect("separate, non-empty session and certificate identities must bind");
    assert_eq!(binding.ephemeral().session_id(), &SESSION_ID);
    assert_eq!(binding.certificate_sha256(), &CERTIFICATE_SHA256);
}

#[test]
fn canonical_digest_changes_for_every_stable_ephemeral_and_certificate_claim() {
    let base = RuntimeSessionBinding::new(
        stable_binding(),
        DaemonInstanceId::from_bytes(UUID_V7_INSTANCE),
        1,
        SESSION_ID,
        7,
        Sensitivity::Internal,
        CERTIFICATE_SHA256,
    )
    .unwrap();
    let variants = [
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 3],
            ApiPrincipalId::new("local-owner").unwrap(),
            UUID_V7_LINEAGE.parse().unwrap(),
            "local-default",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        StableRuntimeBinding::new(
            UUID_V7_INSTANCE,
            ApiPrincipalId::new("other-owner").unwrap(),
            UUID_V7_LINEAGE.parse().unwrap(),
            "local-default",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        StableRuntimeBinding::new(
            UUID_V7_INSTANCE,
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003".parse().unwrap(),
            "local-default",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        StableRuntimeBinding::new(
            UUID_V7_INSTANCE,
            ApiPrincipalId::new("local-owner").unwrap(),
            UUID_V7_LINEAGE.parse().unwrap(),
            "other-profile",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        StableRuntimeBinding::new(
            UUID_V7_INSTANCE,
            ApiPrincipalId::new("local-owner").unwrap(),
            UUID_V7_LINEAGE.parse().unwrap(),
            "local-default",
            [9; 32],
            [4; 32],
        )
        .unwrap(),
        StableRuntimeBinding::new(
            UUID_V7_INSTANCE,
            ApiPrincipalId::new("local-owner").unwrap(),
            UUID_V7_LINEAGE.parse().unwrap(),
            "local-default",
            [3; 32],
            [10; 32],
        )
        .unwrap(),
    ];
    for stable in variants {
        assert_ne!(
            base.canonical_digest(),
            RuntimeSessionBinding::new(
                stable,
                DaemonInstanceId::from_bytes(UUID_V7_INSTANCE),
                1,
                SESSION_ID,
                7,
                Sensitivity::Internal,
                CERTIFICATE_SHA256
            )
            .unwrap()
            .canonical_digest()
        );
    }
    for (daemon, generation, session, epoch, sensitivity, certificate) in [
        (
            DaemonInstanceId::from_bytes([
                1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 3,
            ]),
            1,
            SESSION_ID,
            7,
            Sensitivity::Internal,
            CERTIFICATE_SHA256,
        ),
        (
            DaemonInstanceId::from_bytes(UUID_V7_INSTANCE),
            2,
            SESSION_ID,
            7,
            Sensitivity::Internal,
            CERTIFICATE_SHA256,
        ),
        (
            DaemonInstanceId::from_bytes(UUID_V7_INSTANCE),
            1,
            [9; 16],
            7,
            Sensitivity::Internal,
            CERTIFICATE_SHA256,
        ),
        (
            DaemonInstanceId::from_bytes(UUID_V7_INSTANCE),
            1,
            SESSION_ID,
            8,
            Sensitivity::Internal,
            CERTIFICATE_SHA256,
        ),
        (
            DaemonInstanceId::from_bytes(UUID_V7_INSTANCE),
            1,
            SESSION_ID,
            7,
            Sensitivity::Public,
            CERTIFICATE_SHA256,
        ),
        (
            DaemonInstanceId::from_bytes(UUID_V7_INSTANCE),
            1,
            SESSION_ID,
            7,
            Sensitivity::Internal,
            [9; 32],
        ),
    ] {
        assert_ne!(
            base.canonical_digest(),
            RuntimeSessionBinding::new(
                stable_binding(),
                daemon,
                generation,
                session,
                epoch,
                sensitivity,
                certificate
            )
            .unwrap()
            .canonical_digest()
        );
    }
}
