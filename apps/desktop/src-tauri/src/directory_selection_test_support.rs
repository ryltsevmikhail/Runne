use gocode_api::{
    LaunchSecret, RootAdmissionAuthenticator, RootAdmissionRequest, RootAdmissionVerificationContext, RootHandleControlFrame, RootHandleTransferAuthenticator,
    RootHandleTransferContext, RootHandleTransferOffer, RootHandleTransferReady,
    RootHandleTransferResult, WorkspaceId,
};

pub fn test_admission() -> gocode_platform_desktop::ProtectedRootHandleAdmission {
    let context = RootHandleTransferContext::new(
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
        1,
        10,
        11,
        1_000,
        WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3]),
        1,
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
    let raw = RootAdmissionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([8; 32]).expect("secret").derive_keys(),
    ).issue(RootAdmissionRequest::new(
        RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 100).expect("context"),
        context.workspace_id(), 1, [4; 32], offer.digest(), [5; 16], 30_100,
    ).expect("request")).expect("raw admission");
    let frame = RootHandleControlFrame::Result(RootHandleTransferResult::admitted(&ready, raw, &keys));
    let gocode_api::VerifiedRootHandleControlFrame::Result(result) =
        RootHandleControlFrame::decode_and_verify(&frame.encode_frame(), &keys, &context, 2, 100)
            .expect("verified result")
    else {
        unreachable!("result frame")
    };
    result.into_protected_admission().expect("protected admission")
}
