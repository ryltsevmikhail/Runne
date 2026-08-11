use gocode_api::{
    LaunchSecret, RootAdmissionAuthenticator, RootAdmissionRequest,
    RootAdmissionVerificationContext,
};
use gocode_domain::id::WorkspaceId;

#[test]
fn protected_activation_keys_issue_and_verify_a_root_admission_without_test_support() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let authenticator = RootAdmissionAuthenticator::from_protected_activation(&keys);
    let context =
        RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 1, 1, 1, 10).unwrap();
    let request = RootAdmissionRequest::new(
        context,
        WorkspaceId::from_bytes([4; 16]),
        1,
        [5; 32],
        [6; 16],
        20,
        [8; 32],
    )
    .unwrap();
    let admission = authenticator.issue(request).unwrap();
    let claims = authenticator.verify(admission).unwrap();
    assert_eq!(claims.workspace_id(), WorkspaceId::from_bytes([4; 16]));
    assert_eq!(claims.expires_at_unix_millis(), 20);
}

#[test]
fn admissions_from_another_protected_activation_key_are_rejected() {
    let issuer_keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let verifier_keys = LaunchSecret::from_bytes([9; 32]).unwrap().derive_keys();
    let issuer = RootAdmissionAuthenticator::from_protected_activation(&issuer_keys);
    let verifier = RootAdmissionAuthenticator::from_protected_activation(&verifier_keys);
    let context =
        RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 1, 1, 1, 10).unwrap();
    let admission = issuer
        .issue(
            RootAdmissionRequest::new(
                context,
                WorkspaceId::from_bytes([4; 16]),
                1,
                [5; 32],
                [6; 16],
                20,
                [8; 32],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(verifier.verify(admission).is_err());
}
