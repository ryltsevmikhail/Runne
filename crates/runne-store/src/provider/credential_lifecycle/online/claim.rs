use runne_provider::{
    ClaimCredentialOperation, CredentialLifecycleError, CredentialOperationSnapshot,
    CredentialOperationState, CredentialTicketAttempt, IssueCredentialTicketDigest,
    IssuedCredentialTicketAttempt,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{Head, load_head, map_sql, snapshot};

pub(super) fn issue_ticket(
    store: &SqliteProviderCredentialLifecycleStore,
    input: IssueCredentialTicketDigest,
) -> Result<IssuedCredentialTicketAttempt, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    if operation.state() != CredentialOperationState::Prepared {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    let attached: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT continuation_binding_digest
             FROM provider_credential_process_attachments
             WHERE operation_id=?1 AND state='ATTACHED'",
            [input.operation_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    if attached.as_deref() != Some(&input.continuation_binding_digest().as_bytes()) {
        return Err(CredentialLifecycleError::Conflict);
    }
    let head = load_head(&transaction, operation.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    if !claim_head_matches(&operation, &head)? {
        return Err(CredentialLifecycleError::Conflict);
    }
    let effective_now = head.observed_at.max((store.now)());
    let begin_expiry: i64 = transaction
        .query_row(
            "SELECT begin_proof_expires_at_high_water FROM provider_credential_operations WHERE operation_id=?1",
            [input.operation_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(map_sql)?;
    let recovery_expiry = match super::recovery_claim::lease_deadline(
        &transaction, input.operation_id(), input.continuation_binding_digest(), effective_now,
    ) {
        Err(CredentialLifecycleError::StaleLease) => {
            advance_observed_at_high_water(&transaction, operation.provider(), effective_now)?;
            transaction.commit().map_err(map_sql)?;
            return Err(CredentialLifecycleError::StaleLease);
        }
        result => result?,
    };
    if recovery_expiry.is_none() && (begin_expiry <= 0 || effective_now >= begin_expiry) {
        advance_observed_at_high_water(&transaction, operation.provider(), effective_now)?;
        transaction.commit().map_err(map_sql)?;
        return Err(CredentialLifecycleError::StaleLease);
    }
    let previous: Option<(i64, String)> = transaction.query_row("SELECT attempt, state FROM provider_credential_ticket_attempts WHERE operation_id=?1 ORDER BY attempt DESC LIMIT 1", [input.operation_id().as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(map_sql)?;
    let attempt = match previous {
        Some((attempt, state)) => {
            let next = attempt
                .checked_add(1)
                .ok_or(CredentialLifecycleError::CorruptState)?;
            if state == "ISSUED" {
                transaction.execute("UPDATE provider_credential_ticket_attempts SET state='EXPIRED' WHERE operation_id=?1 AND attempt=?2 AND state='ISSUED'", params![input.operation_id().as_bytes().as_slice(), attempt]).map_err(map_sql)?;
                transaction.execute("UPDATE provider_credential_ticket_attempts SET state='TOMBSTONED', terminal_digest=ticket_digest WHERE operation_id=?1 AND attempt=?2 AND state='EXPIRED'", params![input.operation_id().as_bytes().as_slice(), attempt]).map_err(map_sql)?;
            }
            next
        }
        None => 1,
    };
    let attempt = CredentialTicketAttempt::new(
        u64::try_from(attempt).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let expires = effective_now
        .checked_add(input.ticket_ttl_seconds())
        .ok_or(CredentialLifecycleError::InvalidInput)?;
    let expires = expires.min(recovery_expiry.unwrap_or(i64::MAX));
    transaction.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'ISSUED')", params![input.operation_id().as_bytes().as_slice(), attempt.get(), input.ticket_digest().as_bytes().as_slice(), input.continuation_binding_digest().as_bytes().as_slice(), effective_now, expires]).map_err(map_ticket_issue_sql)?;
    advance_observed_at_high_water(&transaction, operation.provider(), effective_now)?;
    transaction.commit().map_err(map_sql)?;
    store
        .enrollment_authority
        .hydrate_issued_credential_ticket_attempt(operation, attempt, effective_now, expires)
        .map_err(|_| CredentialLifecycleError::CorruptState)
}

fn advance_observed_at_high_water(
    transaction: &rusqlite::Transaction<'_>,
    provider: &runne_provider::ProviderId,
    effective_now: i64,
) -> Result<(), CredentialLifecycleError> {
    let changed = transaction
        .execute(
            "UPDATE provider_credential_authority_heads SET observed_at_high_water=?1
             WHERE provider_id=?2 AND observed_at_high_water<=?1",
            params![effective_now, provider.as_str()],
        )
        .map_err(map_sql)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(CredentialLifecycleError::Conflict)
    }
}

fn map_ticket_issue_sql(error: rusqlite::Error) -> CredentialLifecycleError {
    match &error {
        rusqlite::Error::SqliteFailure(_, Some(message))
            if message == "credential ticket begin proof expiry is stale" =>
        {
            CredentialLifecycleError::StaleLease
        }
        _ => map_sql(error),
    }
}

pub(super) fn claim(
    store: &SqliteProviderCredentialLifecycleStore,
    input: ClaimCredentialOperation,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    store
        .enrollment_authority
        .validate_issued_credential_ticket_attempt(input.receipt())
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    let admission_digest = store
        .enrollment_authority
        .validate_claim_operation(&input)
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    if admission_digest != input.process_release_binding_digest() {
        return Err(CredentialLifecycleError::Conflict);
    }
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    if operation.state() != CredentialOperationState::Prepared
        || operation != input.receipt().operation().clone()
        || operation.installation_owner_id() != input.installation_owner_id()
        || operation.provider() != input.provider_id()
        || operation.action() != input.action()
        || operation.allocated_credential_version() != input.allocated_credential_version()
        || operation.target_credential_version() != input.target_credential_version()
        || operation.lifecycle_revision() != input.expected_lifecycle_revision()
        || operation.fence() != input.expected_prior_fence()
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let head = load_head(&transaction, operation.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    if !claim_head_matches(&operation, &head)? {
        return Err(CredentialLifecycleError::Conflict);
    }
    let ticket: Option<(i64, i64)> = transaction
        .query_row(
            "SELECT issued_at, expires_at FROM provider_credential_ticket_attempts
         WHERE operation_id=?1 AND attempt=?2 AND ticket_digest=?3
           AND continuation_binding_digest=?4 AND issued_at=?5 AND expires_at=?6
           AND state='ISSUED'",
            params![
                input.operation_id().as_bytes().as_slice(),
                input.ticket_attempt().get(),
                input.ticket_digest().as_bytes().as_slice(),
                input.continuation_binding_digest().as_bytes().as_slice(),
                input.issued_at_high_water(),
                input.expires_at_high_water(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_sql)?;
    let (issued_at, expires_at) = ticket.ok_or(CredentialLifecycleError::Conflict)?;
    let effective_now = head.observed_at.max((store.now)());
    if effective_now < issued_at {
        return Err(CredentialLifecycleError::StaleLease);
    }
    let changed = transaction
        .execute(
            "UPDATE provider_credential_authority_heads SET observed_at_high_water=?1
         WHERE provider_id=?2 AND observed_at_high_water<=?1",
            params![effective_now, operation.provider().as_str()],
        )
        .map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    if effective_now >= expires_at {
        let changed = transaction
            .execute(
                "UPDATE provider_credential_ticket_attempts SET state='EXPIRED'
             WHERE operation_id=?1 AND attempt=?2 AND state='ISSUED'",
                params![
                    input.operation_id().as_bytes().as_slice(),
                    input.ticket_attempt().get()
                ],
            )
            .map_err(map_sql)?;
        if changed != 1 {
            return Err(CredentialLifecycleError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE provider_credential_ticket_attempts
             SET state='TOMBSTONED', terminal_digest=ticket_digest
             WHERE operation_id=?1 AND attempt=?2 AND state='EXPIRED'",
                params![
                    input.operation_id().as_bytes().as_slice(),
                    input.ticket_attempt().get()
                ],
            )
            .map_err(map_sql)?;
        if changed != 1 {
            return Err(CredentialLifecycleError::Conflict);
        }
        transaction.commit().map_err(map_sql)?;
        return Err(CredentialLifecycleError::StaleLease);
    }
    super::recovery_claim::consume(&transaction, &store.enrollment_authority, &input, effective_now)?;
    let changed = transaction.execute("UPDATE provider_credential_ticket_attempts SET state='CLAIMED' WHERE operation_id=?1 AND attempt=?2 AND ticket_digest=?3 AND continuation_binding_digest=?4 AND issued_at=?5 AND expires_at=?6 AND state='ISSUED' AND expires_at>?7", params![input.operation_id().as_bytes().as_slice(), input.ticket_attempt().get(), input.ticket_digest().as_bytes().as_slice(), input.continuation_binding_digest().as_bytes().as_slice(), input.issued_at_high_water(), input.expires_at_high_water(), effective_now]).map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    let changed = transaction.execute("UPDATE provider_credential_operations SET state='CLAIMED', continuation_binding_digest=?1, process_release_binding_digest=?2, claimed_ticket_attempt=?3, updated_at=?4 WHERE operation_id=?5 AND state='PREPARED'", params![input.continuation_binding_digest().as_bytes().as_slice(), input.process_release_binding_digest().as_bytes().as_slice(), input.ticket_attempt().get(), effective_now, input.operation_id().as_bytes().as_slice()]).map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    let changed = transaction
        .execute(
            "UPDATE provider_credential_ticket_attempts
         SET state='TOMBSTONED', terminal_digest=ticket_digest
         WHERE operation_id=?1 AND attempt=?2 AND state='CLAIMED'",
            params![
                input.operation_id().as_bytes().as_slice(),
                input.ticket_attempt().get()
            ],
        )
        .map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    let result = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

pub(super) fn claim_head_matches(
    operation: &CredentialOperationSnapshot,
    head: &Head,
) -> Result<bool, CredentialLifecycleError> {
    if head.hard_fenced {
        return Ok(false);
    }
    let offset = i64::from(operation.action() == runne_provider::CredentialOperationAction::Revoke);
    let lifecycle = i64::try_from(operation.lifecycle_revision().get())
        .map_err(|_| CredentialLifecycleError::CorruptState)?
        .checked_add(offset)
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let fence = i64::try_from(operation.fence().get())
        .map_err(|_| CredentialLifecycleError::CorruptState)?
        .checked_add(offset)
        .ok_or(CredentialLifecycleError::CorruptState)?;
    if operation.action() == runne_provider::CredentialOperationAction::LegacySourceCleanup {
        return Ok(operation.metadata().legacy_cleanup_binding().is_some()
            && head.lifecycle >= lifecycle && head.fence >= fence);
    }
    Ok(head.lifecycle == lifecycle && head.fence == fence)
}
