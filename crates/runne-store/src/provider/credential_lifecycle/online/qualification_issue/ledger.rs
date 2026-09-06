use runne_provider::{CredentialLifecycleError, CredentialTicketAttempt, ProviderQualificationAdmissionFence};
use rusqlite::{Transaction, params};
use super::map_sql;

pub(super) fn reject_replay(transaction: &Transaction<'_>, input: &ProviderQualificationAdmissionFence)
    -> Result<(), CredentialLifecycleError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_qualification_admission_fences
         WHERE operation_id=?1 OR context_id=?2 OR context_nonce=?3 OR ticket_id=?4 OR ticket_nonce=?5)",
        params![input.operation_id().as_bytes().as_slice(), input.context_id().as_slice(),
            input.context_nonce().as_slice(), input.ticket_id().as_slice(), input.ticket_nonce().as_slice()],
        |row| row.get(0),
    ).map_err(map_sql)?;
    if exists { Err(CredentialLifecycleError::Conflict) } else { Ok(()) }
}

pub(super) fn insert(transaction: &Transaction<'_>, input: &ProviderQualificationAdmissionFence,
    attempt: CredentialTicketAttempt, now: i64) -> Result<(), CredentialLifecycleError> {
    transaction.execute(
        "INSERT INTO provider_qualification_admission_fences
        (operation_id,attempt,context_id,context_nonce,ticket_id,ticket_nonce,ticket_sha256,
        scenario_id,selector,process_role,candidate_sha256,raw_v3_tuple_sha256,source_revision,
        workflow_run_id,namespace_sha256,context_issued_at,context_expires_at,ticket_issued_at,
        ticket_expires_at,protected_session_digest,runtime_authority_id,database_generation,
        launch_generation,supervisor_generation,verified_at,committed_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26)",
        params![input.operation_id().as_bytes().as_slice(), attempt.get(), input.context_id().as_slice(),
            input.context_nonce().as_slice(), input.ticket_id().as_slice(), input.ticket_nonce().as_slice(),
            input.ticket_sha256().as_slice(), input.scenario(), input.selector(), input.process_role(),
            input.candidate_sha256().as_slice(), input.raw_v3_tuple_sha256().as_slice(), input.source_revision().as_slice(),
            input.workflow_run_id(), input.namespace_sha256().as_slice(), input.context_issued_at(),
            input.context_expires_at(), input.ticket_issued_at(), input.ticket_expires_at(),
            input.protected_session_digest().as_bytes().as_slice(), input.runtime_authority_id().as_slice(),
            input.database_generation(), input.launch_generation(), input.supervisor_generation(), input.verified_at(), now],
    ).map_err(map_sql)?;
    Ok(())
}
