use runne_api::{
    ApprovalDecisionAck, ApprovalState, AuthoritativeCommandOutcome, CommandReconciliationContext,
    CommandReconciliationWitness, CommandReconciliationWitnessRef,
};
use runne_application::command_reconciliation::CommandReconciliationEvidence as Evidence;
use runne_application::command_reconciliation::CommandReconciliationRepositoryError as Error;
use runne_domain::id::{ApprovalId, TaskRunId};
use rusqlite::{OptionalExtension, Transaction};

pub(super) fn lookup(
    transaction: &Transaction<'_>,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<Evidence, Error> {
    let CommandReconciliationWitnessRef::ApprovalDecision {
        approval_id,
        expected_version,
        decision,
        action_digest,
        policy_revision,
        renderer_generation,
    } = witness.view()
    else {
        return Err(Error::InvariantViolation);
    };
    let row = transaction
        .query_row(
            "SELECT approval_id, task_run_id, principal_id, action_digest, policy_revision,
                    request_version, renderer_generation, state, decision_idempotency_key,
                    decision_principal_id, decision
             FROM approvals WHERE decision_command_id = ?1",
            [context.command_id().as_bytes()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| Error::Unavailable)?;
    let Some((
        stored_id,
        task_run_id,
        principal,
        stored_digest,
        policy,
        version,
        generation,
        state,
        key,
        decision_principal,
        stored_decision,
    )) = row
    else {
        let collision: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM approvals WHERE decision_idempotency_key = ?1)",
                [context.idempotency_key().as_str()],
                |row| row.get(0),
            )
            .map_err(|_| Error::Unavailable)?;
        return if collision {
            Err(Error::Conflict)
        } else {
            Ok(Evidence::NotCommitted)
        };
    };
    let stored_id = stored_id
        .parse::<ApprovalId>()
        .map_err(|_| Error::InvariantViolation)?;
    let task_run_id = task_run_id
        .parse::<TaskRunId>()
        .map_err(|_| Error::InvariantViolation)?;
    if stored_id != approval_id
        || principal != context.principal().as_str()
        || key.as_deref() != Some(context.idempotency_key().as_str())
        || decision_principal.as_deref() != Some(context.principal().as_str())
        || stored_digest.as_slice() != action_digest
        || policy != policy_revision
        || generation != renderer_generation
        || version
            != expected_version
                .checked_add(1)
                .ok_or(Error::InvariantViolation)?
    {
        return Err(Error::Conflict);
    }
    let state = match (state, stored_decision, decision) {
        (2, Some(1), runne_api::ApprovalDecision::Approve) => ApprovalState::Approved,
        (3, Some(2), runne_api::ApprovalDecision::Deny) => ApprovalState::Denied,
        (2, Some(1), runne_api::ApprovalDecision::Deny) => return Err(Error::Conflict),
        (3, Some(2), runne_api::ApprovalDecision::Approve) => return Err(Error::Conflict),
        (4, _, _) => ApprovalState::Expired,
        (5, _, _) => ApprovalState::Cancelled,
        _ => return Err(Error::InvariantViolation),
    };
    if state == ApprovalState::Expired || state == ApprovalState::Cancelled {
        return Err(Error::InvariantViolation);
    }
    let ack = ApprovalDecisionAck::new(approval_id, task_run_id, version, state)
        .map_err(|_| Error::InvariantViolation)?;
    Ok(Evidence::Terminal(Box::new(
        AuthoritativeCommandOutcome::approval_decision(ack),
    )))
}
