use runne_api::{
    LaunchSecret, RootAdmissionAuthenticator, RootAdmissionRequest,
    RootAdmissionVerificationContext, RootHandleControlFrame, RootHandleTransferAuthenticator,
    RootHandleTransferContext, RootHandleTransferOffer, RootHandleTransferReady,
    RootHandleTransferResult, WorkspaceId,
};

fn context() -> RootHandleTransferContext {
    RootHandleTransferContext::new(
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
        1,
        10,
        11,
        1000,
        WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3]),
        1,
        [4; 16],
        100,
        30_100,
    )
    .unwrap()
}

#[test]
fn result_v3_authenticates_distinct_admission_digest_and_rejects_v2_magic() {
    let keys = RootHandleTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys(),
    );
    let offer = RootHandleTransferOffer::new(context(), 1, &keys).unwrap();
    let ready = RootHandleTransferReady::new(&offer, &keys);
    let admission = RootAdmissionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys(),
    )
    .issue(
        RootAdmissionRequest::new(
            RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 100).unwrap(),
            WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3]),
            1,
            [4; 32],
            offer.digest(),
            [5; 16],
            30_100,
        )
        .unwrap(),
    )
    .unwrap();
    let admission_digest = admission.admission_digest();
    let frame = RootHandleControlFrame::Result(RootHandleTransferResult::admitted(
        &ready, admission, &keys,
    ))
    .encode_frame();
    let runne_api::VerifiedRootHandleControlFrame::Result(result) =
        RootHandleControlFrame::decode_and_verify(&frame, &keys, &context(), 2, 100).unwrap()
    else {
        unreachable!("result")
    };
    let wrapped = result.into_protected_admission().unwrap();
    assert_eq!(wrapped.admission_digest(), admission_digest);
    assert_ne!(wrapped.admission_digest(), offer.digest());

    let mut altered_digest = frame.clone();
    altered_digest[4 + 158] ^= 1;
    assert!(
        RootHandleControlFrame::decode_and_verify(&altered_digest, &keys, &context(), 2, 100)
            .is_err()
    );
    let mut altered_offer = frame.clone();
    altered_offer[4 + 125] ^= 1;
    assert!(
        RootHandleControlFrame::decode_and_verify(&altered_offer, &keys, &context(), 2, 100)
            .is_err()
    );
    let mut v2 = frame;
    v2[4..12].copy_from_slice(b"GCRHCTL2");
    assert!(RootHandleControlFrame::decode_and_verify(&v2, &keys, &context(), 2, 100).is_err());
}
