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
        7,
        Sensitivity::Internal,
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
