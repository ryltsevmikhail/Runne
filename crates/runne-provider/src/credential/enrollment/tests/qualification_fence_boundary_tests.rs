use super::super::{
    CredentialBindingDigest, CredentialEnrollmentAuthorityPair, CredentialEnrollmentError,
    CredentialOperationId, CredentialTicketAttempt, ProviderQualificationAdmissionFence,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ZeroField {
    ContextId,
    ContextNonce,
    TicketId,
    TicketNonce,
    TicketDigest,
    Candidate,
    RawTuple,
    SourceRevision,
    Namespace,
    RuntimeAuthority,
}

fn byte32(field: ZeroField, zero: Option<ZeroField>, value: u8) -> [u8; 32] {
    if Some(field) == zero {
        [0; 32]
    } else {
        [value; 32]
    }
}

fn input_with_zero(
    zero: Option<ZeroField>,
    generations: (u64, u64, u64),
) -> Result<ProviderQualificationAdmissionFence, CredentialEnrollmentError> {
    ProviderQualificationAdmissionFence::new(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        byte32(ZeroField::ContextId, zero, 2),
        byte32(ZeroField::ContextNonce, zero, 3),
        byte32(ZeroField::TicketId, zero, 4),
        byte32(ZeroField::TicketNonce, zero, 5),
        byte32(ZeroField::TicketDigest, zero, 6),
        "macos-xpc-dpk-v1",
        "kill_before_native_effect",
        "service",
        byte32(ZeroField::Candidate, zero, 7),
        byte32(ZeroField::RawTuple, zero, 8),
        if zero == Some(ZeroField::SourceRevision) {
            [0; 20]
        } else {
            [9; 20]
        },
        "run-42",
        byte32(ZeroField::Namespace, zero, 10),
        100,
        180,
        100,
        200,
        CredentialBindingDigest::from_measured([11; 32]).unwrap(),
        if zero == Some(ZeroField::RuntimeAuthority) {
            [0; 16]
        } else {
            [12; 16]
        },
        generations.0,
        generations.1,
        generations.2,
        120,
    )
}

#[test]
fn qualification_fence_rejects_each_zero_identity_and_generation() {
    for field in [
        ZeroField::ContextId,
        ZeroField::ContextNonce,
        ZeroField::TicketId,
        ZeroField::TicketNonce,
        ZeroField::TicketDigest,
        ZeroField::Candidate,
        ZeroField::RawTuple,
        ZeroField::SourceRevision,
        ZeroField::Namespace,
        ZeroField::RuntimeAuthority,
    ] {
        assert!(input_with_zero(Some(field), (13, 14, 15)).is_err());
    }
    for generations in [(0, 14, 15), (13, 0, 15), (13, 14, 0)] {
        assert!(input_with_zero(None, generations).is_err());
    }
    assert!(CredentialOperationId::from_bytes([0; 16]).is_err());
    assert!(CredentialBindingDigest::from_measured([0; 32]).is_err());
}

#[test]
fn qualification_receipt_enforces_commit_temporal_boundaries() {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let input = super::qualification_fence_contract_tests::valid_input();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    for committed_at in [120, 169] {
        assert!(
            store
                .hydrate_qualification_admission_fence_receipt_for_test(
                    &input,
                    attempt,
                    committed_at,
                    170,
                )
                .is_ok()
        );
    }
    for (committed_at, provider_expires_at) in [(119, 170), (170, 170), (120, 120), (120, 0)] {
        assert_eq!(
            store
                .hydrate_qualification_admission_fence_receipt_for_test(
                    &input,
                    attempt,
                    committed_at,
                    provider_expires_at,
                )
                .err(),
            Some(CredentialEnrollmentError::InvalidInput)
        );
    }
    assert!(CredentialTicketAttempt::new(0).is_err());
}
