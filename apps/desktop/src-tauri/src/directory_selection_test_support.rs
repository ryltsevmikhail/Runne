use runne_api::{
    LaunchSecret, RootAdmissionAuthenticator, RootAdmissionRequest, RootAdmissionVerificationContext, RootHandleControlFrame, RootHandleTransferAuthenticator,
    RootHandleTransferContext, RootHandleTransferOffer, RootHandleTransferReady,
    RootHandleTransferResult, WorkspaceId,
};

pub fn test_root_handle(path: &std::path::Path) -> runne_platform_desktop::VerifiedRootHandle {
    let canonical = std::fs::canonicalize(path).expect("canonical root path");
    runne_platform_desktop::VerifiedRootHandle::open(&canonical).expect("root")
}

pub fn test_admission_for(workspace_id: WorkspaceId, expected_version: u64) -> runne_platform_desktop::ProtectedRootHandleAdmission {
    let context = RootHandleTransferContext::new(
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
        1,
        10,
        11,
        1_000,
        workspace_id,
        expected_version,
        [4; 16],
        100,
        30_100,
    )
    .expect("context");
    let keys = RootHandleTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32])
            .expect("secret")
            .derive_keys(),
    );
    let offer = RootHandleTransferOffer::new(context.clone(), 1, &keys).expect("offer");
    let ready = RootHandleTransferReady::new(&offer, &keys);
    let admission_keys = RootAdmissionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([8; 32]).expect("secret").derive_keys(),
    );
    let raw = admission_keys.issue(RootAdmissionRequest::new(
        RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 100).expect("context"),
        context.workspace_id(), expected_version, [4; 32], offer.digest(), [5; 16], 30_100,
    ).expect("request")).expect("raw admission");
    let frame = RootHandleControlFrame::Result(RootHandleTransferResult::admitted(&ready, raw, &keys));
    let runne_api::VerifiedRootHandleControlFrame::Result(result) =
        RootHandleControlFrame::decode_and_verify(&frame.encode_frame(), &keys, &context, 2, 100)
            .expect("verified result")
    else {
        unreachable!("result frame")
    };
    result
        .into_protected_admission(&admission_keys, offer.digest())
        .expect("protected admission conversion")
        .expect("protected admission present")
}

pub fn test_admission() -> runne_platform_desktop::ProtectedRootHandleAdmission {
    test_admission_for(
        WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3]),
        1,
    )
}
