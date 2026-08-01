use std::path::PathBuf;

use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError,
    LaunchAuthorityValidationV1, LaunchSecret, PendingFirstActivationV1,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedReadyV1, ProtectedRenewRequestV1, ProtectedRenewTicketV1, ProtectedRuntimeProfileV1,
    ProtectedShutdownAckV1, ProtectedShutdownV1, StableRuntimeBindingV1,
};

const AUTHORITY_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const HOST_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
const LINEAGE_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];
const INSTANCE_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
];
const SESSION_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
];

fn executable() -> ExecutableIdentityV1 {
    ExecutableIdentityV1::new([0x11; 32], [0x12; 32], 4_096).expect("executable identity")
}

fn profile() -> ProtectedRuntimeProfileV1 {
    ProtectedRuntimeProfileV1::new(
        "gocode-bundled-runtime/1",
        1,
        "gocode-ui-client/1",
        [0x21; 32],
        [0x22; 32],
    )
    .expect("protected profile")
}

fn stable() -> StableRuntimeBindingV1 {
    StableRuntimeBindingV1::new(
        AUTHORITY_ID,
        "local-owner",
        LINEAGE_ID,
        "gocode-ui-client/1",
        [0x21; 32],
        [0x22; 32],
    )
    .expect("stable binding")
}

fn launch(secret: LaunchSecret) -> ProtectedLaunchRequestV1 {
    launch_with_disposition(
        secret,
        ActivationDispositionV1::Existing(Box::new(stable())),
    )
}

fn launch_with_disposition(
    secret: LaunchSecret,
    disposition: ActivationDispositionV1,
) -> ProtectedLaunchRequestV1 {
    ProtectedLaunchRequestV1::new(
        AUTHORITY_ID,
        HOST_ID,
        secret,
        1_000,
        31_000,
        "local-owner",
        profile(),
        executable(),
        PathBuf::from("/private/tmp/gocode-protected-runtime"),
        disposition,
    )
    .expect("launch request")
}
