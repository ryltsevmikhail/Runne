use runne_local_store::{BoundedCanonicalId, CanonicalMutationOutcome, NormalizedMutationCommand};

fn id(value: &str) -> BoundedCanonicalId {
    BoundedCanonicalId::parse(value.as_bytes()).expect("canonical UUIDv7")
}

#[test]
fn approval_response_command_round_trips_with_all_security_bindings() {
    let command = NormalizedMutationCommand::ApprovalRespond {
        approval_id: id("018f0b7e-7b6a-7a2a-8a11-111111111111"),
        expected_version: 3,
        decision: runne_local_store::ApprovalDecisionKind::Approve,
        action_digest: [7; 32],
        policy_revision: 11,
        renderer_generation: 19,
    };

    let encoded = command.encode().expect("valid command");
    assert_eq!(
        NormalizedMutationCommand::decode(&encoded).unwrap(),
        command
    );
}

#[test]
fn approval_response_outcome_correlates_to_command_and_round_trips() {
    let approval_id = id("018f0b7e-7b6a-7a2a-8a11-222222222222");
    let command = NormalizedMutationCommand::ApprovalRespond {
        approval_id: approval_id.clone(),
        expected_version: 4,
        decision: runne_local_store::ApprovalDecisionKind::Deny,
        action_digest: [9; 32],
        policy_revision: 12,
        renderer_generation: 20,
    };
    let outcome = CanonicalMutationOutcome::ApprovalRespond {
        approval_id,
        new_version: 5,
        state: runne_local_store::ApprovalOutcomeState::Denied,
    };

    assert!(outcome.correlates_to_command(&command));
    let encoded = outcome.encode().expect("valid outcome");
    assert_eq!(CanonicalMutationOutcome::decode(&encoded).unwrap(), outcome);
}

#[test]
fn approval_response_rejects_zero_security_versions_and_digest() {
    let command = NormalizedMutationCommand::ApprovalRespond {
        approval_id: id("018f0b7e-7b6a-7a2a-8a11-333333333333"),
        expected_version: 0,
        decision: runne_local_store::ApprovalDecisionKind::Approve,
        action_digest: [0; 32],
        policy_revision: 0,
        renderer_generation: 0,
    };

    assert!(command.encode().is_err());
}
