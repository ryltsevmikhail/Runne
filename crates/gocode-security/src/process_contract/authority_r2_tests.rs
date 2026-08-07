use super::ProcessContractError;
use super::authority_tests::{authority, intent, lifecycle};

#[test]
fn swapped_lifecycle_material_is_rejected_without_consuming_the_valid_call() {
    let authority = authority();
    let first_lifecycle = lifecycle(20);
    let second_lifecycle = lifecycle(30);
    let first = authority.bind_call(first_lifecycle.clone()).unwrap();
    let second = authority.bind_call(second_lifecycle.clone()).unwrap();
    let first_intent = intent(first_lifecycle, 40);
    let second_intent = intent(second_lifecycle, 41);
    let first_capability = first.issue_capability(&first_intent, 20).unwrap();
    let first_approval = first.approve(&first_intent, 20, true).unwrap();
    let second_capability = second.issue_capability(&second_intent, 20).unwrap();
    let second_approval = second.approve(&second_intent, 20, true).unwrap();

    assert!(matches!(
        first.validate(
            first_intent.clone(),
            Some(&second_capability),
            Some(&second_approval),
            10
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    assert!(
        first
            .validate(
                first_intent,
                Some(&first_capability),
                Some(&first_approval),
                10
            )
            .is_ok()
    );
}

#[test]
fn preflight_is_non_consuming_until_one_final_validation() {
    let authority = authority();
    let lifecycle = lifecycle(20);
    let boundary = authority.bind_call(lifecycle.clone()).unwrap();
    let intent = intent(lifecycle, 40);
    let capability = boundary.issue_capability(&intent, 20).unwrap();
    let approval = boundary.approve(&intent, 20, true).unwrap();

    assert_eq!(
        boundary.preflight_authorization(&intent, Some(&capability), Some(&approval), 10),
        Ok(())
    );
    assert_eq!(
        boundary.preflight_authorization(&intent, Some(&capability), Some(&approval), 10),
        Ok(())
    );
    assert!(
        boundary
            .validate(intent.clone(), Some(&capability), Some(&approval), 10)
            .is_ok()
    );
    assert!(matches!(
        boundary.validate(intent, Some(&capability), Some(&approval), 10),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn rejected_preflight_tuple_leaves_approved_tuple_committable() {
    let authority = authority();
    let lifecycle = lifecycle(20);
    let boundary = authority.bind_call(lifecycle.clone()).unwrap();
    let intent = intent(lifecycle, 40);
    let capability = boundary.issue_capability(&intent, 20).unwrap();
    let rejected = boundary.approve(&intent, 20, false).unwrap();
    let approved = boundary.approve(&intent, 20, true).unwrap();

    assert!(matches!(
        boundary.preflight_authorization(&intent, Some(&capability), Some(&rejected), 10),
        Err(ProcessContractError::ApprovalInvalid)
    ));
    assert!(
        boundary
            .validate(intent, Some(&capability), Some(&approved), 10)
            .is_ok()
    );
}

#[test]
fn mismatched_preflight_does_not_consume_the_valid_final_tuple() {
    let authority = authority();
    let first_lifecycle = lifecycle(20);
    let second_lifecycle = lifecycle(30);
    let first = authority.bind_call(first_lifecycle.clone()).unwrap();
    let second = authority.bind_call(second_lifecycle.clone()).unwrap();
    let first_intent = intent(first_lifecycle, 40);
    let second_intent = intent(second_lifecycle, 41);
    let first_capability = first.issue_capability(&first_intent, 20).unwrap();
    let first_approval = first.approve(&first_intent, 20, true).unwrap();
    let second_capability = second.issue_capability(&second_intent, 20).unwrap();

    assert!(matches!(
        first.preflight_authorization(
            &first_intent,
            Some(&second_capability),
            Some(&first_approval),
            10
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    assert!(
        first
            .validate(
                first_intent,
                Some(&first_capability),
                Some(&first_approval),
                10
            )
            .is_ok()
    );
}

#[test]
fn advance_after_preflight_rejects_final_without_consuming() {
    let authority = authority();
    let lifecycle = lifecycle(20);
    let boundary = authority.bind_call(lifecycle.clone()).unwrap();
    let intent = intent(lifecycle, 40);
    let capability = boundary.issue_capability(&intent, 20).unwrap();
    let approval = boundary.approve(&intent, 20, true).unwrap();

    assert_eq!(
        boundary.preflight_authorization(&intent, Some(&capability), Some(&approval), 10),
        Ok(())
    );
    authority.prepare_advance().unwrap().commit().unwrap();
    assert!(matches!(
        boundary.validate(intent, Some(&capability), Some(&approval), 10),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn concurrent_final_validation_has_exactly_one_winner() {
    let authority = authority();
    let lifecycle = lifecycle(20);
    let issued = authority.bind_call(lifecycle.clone()).unwrap();
    let intent = intent(lifecycle.clone(), 40);
    let capability = issued.issue_capability(&intent, 20).unwrap();
    let approval = issued.approve(&intent, 20, true).unwrap();
    let first = authority.bind_call(lifecycle.clone()).unwrap();
    let second = authority.bind_call(lifecycle).unwrap();
    let first_intent = intent.clone();
    let second_intent = intent;
    let capability_ref = &capability;
    let approval_ref = &approval;

    let (first_result, second_result) = std::thread::scope(|scope| {
        let first_task = scope.spawn(move || {
            first.validate(first_intent, Some(capability_ref), Some(approval_ref), 10)
        });
        let second_task = scope.spawn(move || {
            second.validate(second_intent, Some(capability_ref), Some(approval_ref), 10)
        });
        (first_task.join().unwrap(), second_task.join().unwrap())
    });
    assert_eq!(
        usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
        1
    );
}
