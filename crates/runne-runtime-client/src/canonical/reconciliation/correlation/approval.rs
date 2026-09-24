use super::super::reconciliation_wire::{ApprovalStateWire, OutcomeWire};
use super::super::{
    ApprovalDecisionAcknowledgementDto, ApprovalDecisionDto, ApprovalStateDto,
    CommandReconciliationOutcome, CommandReconciliationWitness, RuntimeApiError, invalid_response,
};

pub(super) fn correlate_approval(
    witness: &CommandReconciliationWitness,
    outcome: OutcomeWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    match (witness, outcome) {
        (
            CommandReconciliationWitness::ApprovalDecision {
                approval_id,
                expected_version,
                decision,
                ..
            },
            OutcomeWire::ApprovalDecision {
                approval_id: actual,
                new_version,
                task_run_id,
                state,
            },
        ) if *approval_id == actual
            && expected_version.checked_add(1) == Some(new_version)
            && decision_state_matches(*decision, state) =>
        {
            Ok(CommandReconciliationOutcome::ApprovalDecision(
                ApprovalDecisionAcknowledgementDto::observed(
                    actual,
                    task_run_id,
                    new_version,
                    approval_state(state),
                )
                .map_err(|_| invalid_response())?,
            ))
        }
        _ => Err(invalid_response()),
    }
}

const fn decision_state_matches(
    expected: ApprovalDecisionDto,
    observed: ApprovalStateWire,
) -> bool {
    matches!(
        (expected, observed),
        (ApprovalDecisionDto::Approve, ApprovalStateWire::Approved)
            | (ApprovalDecisionDto::Deny, ApprovalStateWire::Denied)
    )
}

const fn approval_state(value: ApprovalStateWire) -> ApprovalStateDto {
    match value {
        ApprovalStateWire::Approved => ApprovalStateDto::Approved,
        ApprovalStateWire::Denied => ApprovalStateDto::Denied,
        ApprovalStateWire::Expired => ApprovalStateDto::Expired,
        ApprovalStateWire::Cancelled => ApprovalStateDto::Cancelled,
    }
}
