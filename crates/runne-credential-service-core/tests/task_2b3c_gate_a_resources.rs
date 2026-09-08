#![cfg(feature = "test-support")]

use runne_credential_service_core::QualificationResourceBudget;

const FULL_TRANSFER_BYTES: usize = 524_300 + 8_192;

#[test]
fn task_2b3c_rejects_full_transfer_without_partial_resource_charge() {
    let budget = QualificationResourceBudget::new_for_test();
    let mut leases = Vec::new();
    for _ in 0..4 {
        leases.push(
            budget
                .try_acquire_reservation_for_test(FULL_TRANSFER_BYTES)
                .expect("four exact maximum transfers fit"),
        );
    }

    assert!(
        budget
            .try_acquire_reservation_for_test(FULL_TRANSFER_BYTES)
            .is_err()
    );
    assert_eq!(budget.usage_for_test(), (4, FULL_TRANSFER_BYTES * 4, 0));

    drop(leases);
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}

#[test]
fn task_2b3c_limits_verification_permits_without_queueing() {
    let budget = QualificationResourceBudget::new_for_test();
    let first = budget.try_acquire_verification_permit_for_test().unwrap();
    let second = budget.try_acquire_verification_permit_for_test().unwrap();

    assert!(budget.try_acquire_verification_permit_for_test().is_err());
    assert_eq!(budget.usage_for_test(), (0, 0, 2));

    drop(first);
    assert!(budget.try_acquire_verification_permit_for_test().is_ok());
    drop(second);
}
