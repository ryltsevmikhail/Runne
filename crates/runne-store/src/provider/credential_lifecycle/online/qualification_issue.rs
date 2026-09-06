use runne_provider::{CredentialLifecycleError as Error, CredentialOperationAction,
    CredentialOperationState, CredentialTicketAttempt, IssueCredentialTicketDigest,
    IssuedCredentialTicketAttempt, MeasuredQualificationAdmission, ProviderQualificationAdmissionFenceReceipt};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use super::{SqliteProviderCredentialLifecycleStore, rows::{load_head, map_sql, snapshot}};

#[path = "qualification_issue/ledger.rs"]
mod ledger;

pub(super) fn issue(
    store: &SqliteProviderCredentialLifecycleStore, ticket: IssueCredentialTicketDigest,
    admission: MeasuredQualificationAdmission,
) -> Result<(IssuedCredentialTicketAttempt, ProviderQualificationAdmissionFenceReceipt), Error> {
    store.enrollment_authority.validate_measured_qualification(&admission)
        .map_err(|_| Error::Conflict)?;
    let facts = admission.metadata();
    if facts.operation_id() != ticket.operation_id()
        || admission.continuation_binding_digest() != ticket.continuation_binding_digest() {
        return Err(Error::Conflict);
    }
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(map_sql)?;
    let operation = snapshot(&transaction, ticket.operation_id(), &store.enrollment_authority)?;
    if operation.state() != CredentialOperationState::Prepared
        || operation.action() != CredentialOperationAction::Pair {
        return Err(Error::LifecycleClosed);
    }
    let attached: Option<Vec<u8>> = transaction.query_row(
        "SELECT continuation_binding_digest FROM provider_credential_process_attachments
         WHERE operation_id=?1 AND state='ATTACHED'", [ticket.operation_id().as_bytes().as_slice()],
        |row| row.get(0),
    ).optional().map_err(map_sql)?;
    if attached.as_deref() != Some(ticket.continuation_binding_digest().as_bytes().as_slice()) {
        return Err(Error::Conflict);
    }
    let head = load_head(&transaction, operation.provider())?.ok_or(Error::CorruptState)?;
    if !super::claim::claim_head_matches(&operation, &head)? { return Err(Error::Conflict); }
    let effective_now = head.observed_at.max((store.now)());
    let begin_expiry: i64 = transaction.query_row(
        "SELECT begin_proof_expires_at_high_water FROM provider_credential_operations WHERE operation_id=?1",
        [ticket.operation_id().as_bytes().as_slice()], |row| row.get(0),
    ).map_err(map_sql)?;
    if effective_now < facts.verified_at() || effective_now >= facts.effective_expires_at()
        || effective_now >= begin_expiry {
        return Err(Error::StaleLease);
    }
    // Qualification has no cleanup recovery authority; only the original Begin lease applies.
    if super::recovery_claim::lease_deadline(&transaction, ticket.operation_id(),
        ticket.continuation_binding_digest(), effective_now)?.is_some() {
        return Err(Error::LifecycleClosed);
    }
    ledger::reject_replay(&transaction, facts)?;
    // A qualified operation gets one actual attempt. Never rotate an ordinary or consumed attempt.
    let previous: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_credential_ticket_attempts WHERE operation_id=?1)",
        [ticket.operation_id().as_bytes().as_slice()], |row| row.get(0),
    ).map_err(map_sql)?;
    if previous { return Err(Error::Conflict); }
    let attempt = CredentialTicketAttempt::new(1).map_err(|_| Error::CorruptState)?;
    let expires = effective_now.checked_add(ticket.ticket_ttl_seconds()).ok_or(Error::InvalidInput)?
        .min(begin_expiry).min(facts.effective_expires_at());
    transaction.execute(
        "INSERT INTO provider_credential_ticket_attempts
        (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'ISSUED')",
        params![ticket.operation_id().as_bytes().as_slice(), attempt.get(),
            ticket.ticket_digest().as_bytes().as_slice(), ticket.continuation_binding_digest().as_bytes().as_slice(),
            effective_now, expires],
    ).map_err(map_sql)?;
    ledger::insert(&transaction, facts, attempt, effective_now)?;
    let changed = transaction.execute(
        "UPDATE provider_credential_authority_heads SET observed_at_high_water=?1
         WHERE provider_id=?2 AND observed_at_high_water<=?1",
        params![effective_now, operation.provider().as_str()],
    ).map_err(map_sql)?;
    if changed != 1 { return Err(Error::Conflict); }
    #[cfg(test)]
    super::qualification_crash_tests::pause("before");
    transaction.commit().map_err(map_sql)?;
    #[cfg(test)]
    super::qualification_crash_tests::pause("after");
    let issued = store.enrollment_authority.hydrate_issued_credential_ticket_attempt(
        operation, attempt, effective_now, expires,
    ).map_err(|_| Error::CorruptState)?;
    let receipt = store.enrollment_authority.issue_committed_qualification_receipt(admission, &issued)
        .map_err(|_| Error::CorruptState)?;
    Ok((issued, receipt))
}
