use super::super::{
    CredentialBindingDigest, CredentialEnrollmentAuthorityPair, CredentialEnrollmentError,
    CredentialOperationId, CredentialTicketAttempt, ProviderQualificationAdmissionFence,
    ProviderQualificationAdmissionFenceReceipt,
};

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

pub(super) fn valid_input() -> ProviderQualificationAdmissionFence {
    ProviderQualificationAdmissionFence::new(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        [2; 32],
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        "macos-xpc-dpk-v1",
        "kill_before_native_effect",
        "service",
        [7; 32],
        [8; 32],
        [9; 20],
        "run-42",
        [10; 32],
        100,
        180,
        100,
        200,
        digest(11),
        [12; 16],
        13,
        14,
        15,
        120,
    )
    .unwrap()
}

#[test]
fn qualification_fence_input_validates_every_bounded_binding() {
    let input = valid_input();
    assert_eq!(input.operation_id().as_bytes(), [1; 16]);
    assert_eq!(input.context_id(), [2; 32]);
    assert_eq!(input.ticket_nonce(), [5; 32]);
    assert_eq!(input.selector(), "kill_before_native_effect");
    assert_eq!(input.process_role(), "service");
    assert_eq!(input.effective_expires_at(), 180);

    let invalid = |context_id,
                   selector,
                   role,
                   workflow,
                   context_issued,
                   context_expires,
                   ticket_expires,
                   generations: (u64, u64, u64),
                   verified| {
        ProviderQualificationAdmissionFence::new(
            CredentialOperationId::from_bytes([1; 16]).unwrap(),
            context_id,
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            "macos-xpc-dpk-v1",
            selector,
            role,
            [7; 32],
            [8; 32],
            [9; 20],
            workflow,
            [10; 32],
            context_issued,
            context_expires,
            100,
            ticket_expires,
            digest(11),
            [12; 16],
            generations.0,
            generations.1,
            generations.2,
            verified,
        )
    };
    let valid_generations = (13, 14, 15);
    assert!(
        invalid(
            [0; 32],
            "kill_before_native_effect",
            "service",
            "run-42",
            100,
            180,
            200,
            valid_generations,
            120
        )
        .is_err()
    );
    assert!(
        invalid(
            [2; 32],
            "kill_before_native_effect",
            "runtime",
            "run-42",
            100,
            180,
            200,
            valid_generations,
            120
        )
        .is_err()
    );
    assert!(
        invalid(
            [2; 32],
            "unknown",
            "service",
            "run-42",
            100,
            180,
            200,
            valid_generations,
            120
        )
        .is_err()
    );
    assert!(
        invalid(
            [2; 32],
            "kill_before_native_effect",
            "service",
            "run-42\0hidden",
            100,
            180,
            200,
            valid_generations,
            120
        )
        .is_err()
    );
    assert!(
        invalid(
            [2; 32],
            "kill_before_native_effect",
            "service",
            "run-42",
            180,
            180,
            200,
            valid_generations,
            180
        )
        .is_err()
    );
    assert!(
        invalid(
            [2; 32],
            "kill_before_native_effect",
            "service",
            "run-42",
            100,
            1001,
            1001,
            valid_generations,
            120
        )
        .is_err()
    );
    assert!(
        invalid(
            [2; 32],
            "kill_before_native_effect",
            "service",
            "run-42",
            100,
            201,
            200,
            valid_generations,
            120
        )
        .is_err()
    );
    assert!(
        invalid(
            [2; 32],
            "kill_before_native_effect",
            "service",
            "run-42",
            100,
            180,
            200,
            (13, 0, 15),
            120
        )
        .is_err()
    );
}

#[test]
fn qualification_fence_receipt_is_store_sealed_and_exact() {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let input = valid_input();
    let receipt = store
        .hydrate_qualification_admission_fence_receipt_for_test(
            &input,
            CredentialTicketAttempt::new(1).unwrap(),
            130,
            170,
        )
        .unwrap();
    assert_eq!(receipt.operation_id(), input.operation_id());
    assert_eq!(receipt.ticket_attempt().get(), 1);
    assert_eq!(receipt.protected_session_digest(), digest(11));
    assert_eq!(receipt.database_generation(), 13);
    assert_eq!(receipt.launch_generation(), 14);
    assert_eq!(receipt.supervisor_generation(), 15);
    assert_eq!(receipt.effective_expires_at(), 170);
    assert!(
        store
            .validate_qualification_admission_fence_receipt(&receipt)
            .is_ok()
    );

    let (foreign, _) = CredentialEnrollmentAuthorityPair::new().split();
    assert_eq!(
        foreign.validate_qualification_admission_fence_receipt(&receipt),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
}

#[test]
fn qualification_fence_receipt_has_no_clone_debug_or_serde_contract() {
    static_assertions::assert_not_impl_any!(
        ProviderQualificationAdmissionFence:
            Clone,
            Copy,
            std::fmt::Debug,
            serde::Serialize,
            serde::Deserialize<'static>
    );
    static_assertions::assert_not_impl_any!(
        ProviderQualificationAdmissionFenceReceipt:
            Clone,
            Copy,
            std::fmt::Debug,
            serde::Serialize,
            serde::Deserialize<'static>
    );
}
