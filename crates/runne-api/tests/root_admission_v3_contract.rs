use runne_api::{
    LaunchSecret, RootAdmissionAuthenticator, RootAdmissionRequest,
    RootAdmissionVerificationContext, RootHandleAdmissionValidationError, RootHandleControlFrame,
    RootHandleTransferAuthenticator, RootHandleTransferContext, RootHandleTransferOffer,
    RootHandleTransferReady, RootHandleTransferResult, VerifiedRootHandleTransferResult,
    WorkspaceId,
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

fn transfer_context(workspace_id: WorkspaceId, expected_version: u64) -> RootHandleTransferContext {
    RootHandleTransferContext::new(
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
    .expect("transfer context")
}

fn admission_authenticator() -> RootAdmissionAuthenticator {
    RootAdmissionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([8; 32])
            .expect("secret")
            .derive_keys(),
    )
}

fn issue_admission(
    admission_authenticator: &RootAdmissionAuthenticator,
    workspace_id: WorkspaceId,
    expected_version: u64,
    offer_digest: [u8; 32],
) -> runne_api::IssuedRootHandleAdmission {
    admission_authenticator
        .issue(
            RootAdmissionRequest::new(
                RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 100)
                    .expect("admission context"),
                workspace_id,
                expected_version,
                [4; 32],
                offer_digest,
                [5; 16],
                30_100,
            )
            .expect("request"),
        )
        .expect("raw admission")
}

fn verified_admitted_result(
    workspace_id: WorkspaceId,
    expected_version: u64,
) -> (
    VerifiedRootHandleTransferResult,
    [u8; 32],
    RootAdmissionAuthenticator,
) {
    let context = transfer_context(workspace_id, expected_version);
    let transfer_keys = RootHandleTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32])
            .expect("secret")
            .derive_keys(),
    );
    let offer = RootHandleTransferOffer::new(context.clone(), 1, &transfer_keys).expect("offer");
    let ready = RootHandleTransferReady::new(&offer, &transfer_keys);
    let admission_authenticator = admission_authenticator();
    let raw = issue_admission(
        &admission_authenticator,
        workspace_id,
        expected_version,
        offer.digest(),
    );
    let frame = RootHandleControlFrame::Result(RootHandleTransferResult::admitted(
        &ready,
        raw,
        &transfer_keys,
    ));
    let runne_api::VerifiedRootHandleControlFrame::Result(result) =
        RootHandleControlFrame::decode_and_verify(
            &frame.encode_frame(),
            &transfer_keys,
            &context,
            2,
            100,
        )
        .expect("outer result/context MAC")
    else {
        unreachable!("result frame")
    };
    (result, offer.digest(), admission_authenticator)
}

fn assert_redacted(
    error: RootHandleAdmissionValidationError,
    workspace_id: WorkspaceId,
    version: u64,
) {
    let formatted = format!("{}{:?}", error, error);
    assert_eq!(error.to_string(), "invalid root admission");
    assert_eq!(format!("{error:?}"), "Invalid");
    assert!(!formatted.contains(&workspace_id.to_string()));
    assert!(!formatted.contains(&version.to_string()));
    assert!(!formatted.contains("gocode-root-admission"));
    assert!(!formatted.contains('/'));
}

#[test]
fn result_v3_authenticates_distinct_admission_digest_and_rejects_v2_magic() {
    let keys = RootHandleTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys(),
    );
    let offer = RootHandleTransferOffer::new(context(), 1, &keys).unwrap();
    let ready = RootHandleTransferReady::new(&offer, &keys);
    let admission_keys = admission_authenticator();
    let admission = issue_admission(
        &admission_keys,
        WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3]),
        1,
        offer.digest(),
    );
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
    let wrapped = result
        .into_protected_admission(&admission_keys, offer.digest())
        .unwrap()
        .expect("consistent transfer yields a wrapper");
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

#[test]
fn result_rejects_internal_claims_a_v_against_transfer_context_b_w() {
    let transfer_workspace =
        WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2]);
    let claims_workspace =
        WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3]);
    let context = transfer_context(transfer_workspace, 8);
    let transfer_keys = RootHandleTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32])
            .expect("secret")
            .derive_keys(),
    );
    let offer = RootHandleTransferOffer::new(context.clone(), 1, &transfer_keys).expect("offer");
    let ready = RootHandleTransferReady::new(&offer, &transfer_keys);
    let admission_authenticator = RootAdmissionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([8; 32])
            .expect("secret")
            .derive_keys(),
    );
    let raw = admission_authenticator
        .issue(
            RootAdmissionRequest::new(
                RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 100)
                    .expect("admission context"),
                claims_workspace,
                7,
                [4; 32],
                offer.digest(),
                [5; 16],
                30_100,
            )
            .expect("request"),
        )
        .expect("raw admission");
    let frame = RootHandleControlFrame::Result(RootHandleTransferResult::admitted(
        &ready,
        raw,
        &transfer_keys,
    ));
    let runne_api::VerifiedRootHandleControlFrame::Result(result) =
        RootHandleControlFrame::decode_and_verify(
            &frame.encode_frame(),
            &transfer_keys,
            &context,
            2,
            100,
        )
        .expect("outer result/context MAC")
    else {
        unreachable!("result frame")
    };

    let error = result
        .into_protected_admission(&admission_authenticator, offer.digest())
        .expect_err("A/V claims must not yield a wrapper");
    assert_eq!(error.to_string(), "invalid root admission");
    assert_eq!(format!("{error:?}"), "Invalid");
    assert_redacted(error, claims_workspace, 7);
}

#[test]
fn result_rejects_wrong_retained_offer_digest() {
    let workspace = WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2]);
    let (result, offer_digest, admission_authenticator) = verified_admitted_result(workspace, 8);
    let mut retained = offer_digest;
    retained[0] ^= 1;
    let error = result
        .into_protected_admission(&admission_authenticator, retained)
        .expect_err("mismatched retained offer digest must not yield a wrapper");
    assert_eq!(error.to_string(), "invalid root admission");
    assert_eq!(format!("{error:?}"), "Invalid");
    assert_redacted(error, workspace, 8);
}

#[test]
fn signed_rejection_without_admission_converts_to_none() {
    let workspace = WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2]);
    let context = transfer_context(workspace, 8);
    let transfer_keys = RootHandleTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32])
            .expect("secret")
            .derive_keys(),
    );
    let offer = RootHandleTransferOffer::new(context.clone(), 1, &transfer_keys).expect("offer");
    let ready = RootHandleTransferReady::new(&offer, &transfer_keys);
    let frame =
        RootHandleControlFrame::Result(RootHandleTransferResult::rejected(&ready, &transfer_keys));
    let runne_api::VerifiedRootHandleControlFrame::Result(result) =
        RootHandleControlFrame::decode_and_verify(
            &frame.encode_frame(),
            &transfer_keys,
            &context,
            2,
            100,
        )
        .expect("outer result/context MAC")
    else {
        unreachable!("result frame")
    };
    let admission = result
        .into_protected_admission(&admission_authenticator(), offer.digest())
        .expect("clean signed rejection carries no admission");
    assert!(admission.is_none());
}
