use crate::{
    ClientMutationDisposition, CommandRef, MutationIdentity, MutationRecord, OptionalExtension,
    OutcomeRef, SecurityStateError,
};

pub(crate) fn load_record(
    connection: &rusqlite::Connection,
    identity: MutationIdentity,
) -> Result<Option<MutationRecord>, SecurityStateError> {
    let row: Option<(String,String,Vec<u8>,i64,Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>,i64,String,Option<String>,Option<Vec<u8>>,Option<Vec<u8>>,String,i64,i64)> = connection.query_row("SELECT operation_kind,target_kind,target_id,expected_version,semantic_digest,normalized_command,canonical_outcome,resend_count,client_disposition,runtime_disposition,command_ref,outcome_ref,recovery_summary,created_at,updated_at FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND idempotency_key=?3", rusqlite::params![identity.runtime().to_vec(),identity.principal().to_vec(),identity.idempotency_key()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?))).optional()?;
    let Some((
        operation,
        target_kind,
        target,
        version,
        semantic,
        command_bytes,
        outcome_bytes,
        resend,
        state,
        runtime,
        command,
        outcome,
        summary,
        created,
        updated,
    )) = row
    else {
        return Ok(None);
    };
    if operation != identity.operation_name()
        || target_kind != identity.target_name()
        || target != identity.target()
        || version
            != i64::try_from(identity.expected_version())
                .map_err(|_| SecurityStateError::InvalidIdentity)?
        || semantic != identity.semantic_digest()
        || created < 0
        || updated < created
    {
        return Err(SecurityStateError::IdentityConflict);
    }
    let command = command
        .map(|value| {
            CommandRef::new(
                value
                    .try_into()
                    .map_err(|_| SecurityStateError::IdentityConflict)?,
            )
        })
        .transpose()?;
    let outcome = outcome
        .map(|value| {
            OutcomeRef::new(
                value
                    .try_into()
                    .map_err(|_| SecurityStateError::IdentityConflict)?,
            )
        })
        .transpose()?;
    let normalized_command = command_bytes
        .map(|bytes| {
            let reference = crate::security_ledger_v7::digest::command(&bytes);
            (command.as_ref() == Some(&reference))
                .then(|| crate::NormalizedMutationCommand::decode(&bytes))
                .ok_or(SecurityStateError::IdentityConflict)?
        })
        .transpose()?;
    if normalized_command
        .as_ref()
        .is_some_and(|command| !command.matches_identity(&identity))
    {
        return Err(SecurityStateError::IdentityConflict);
    }
    let canonical_outcome = outcome_bytes
        .map(|bytes| {
            let reference = crate::security_ledger_v7::digest::outcome(&bytes);
            (outcome.as_ref() == Some(&reference))
                .then(|| crate::CanonicalMutationOutcome::decode(&bytes))
                .ok_or(SecurityStateError::IdentityConflict)?
        })
        .transpose()?;
    let resend_count = u8::try_from(resend).map_err(|_| SecurityStateError::InvalidTransition)?;
    let record = MutationRecord {
        identity,
        client_state: crate::security_mutation::parse_state(&state)?,
        runtime_disposition: parse_runtime(runtime)?,
        command_ref: command,
        outcome_ref: outcome,
        normalized_command,
        canonical_outcome,
        resend_count,
        recovery_summary: summary,
        created_at: created,
        updated_at: updated,
    };
    validate_record(&record)?;
    Ok(Some(record))
}
pub(crate) fn prepared_record_v7(
    identity: MutationIdentity,
    command: crate::NormalizedMutationCommand,
    reference: CommandRef,
) -> MutationRecord {
    MutationRecord {
        identity,
        client_state: ClientMutationDisposition::Prepared,
        runtime_disposition: None,
        command_ref: Some(reference),
        outcome_ref: None,
        normalized_command: Some(command),
        canonical_outcome: None,
        resend_count: 0,
        recovery_summary: "prepared".into(),
        created_at: 0,
        updated_at: 0,
    }
}
pub(crate) fn update_v7_record(
    transaction: &rusqlite::Transaction<'_>,
    previous: &MutationRecord,
    update: V7RecordUpdate,
) -> Result<(MutationRecord, bool), SecurityStateError> {
    let V7RecordUpdate {
        state,
        runtime,
        canonical_outcome,
        summary,
        timestamp,
        increment_resend,
    } = update;
    let outcome_bytes = canonical_outcome
        .as_ref()
        .map(crate::CanonicalMutationOutcome::encode)
        .transpose()?;
    let outcome_ref = outcome_bytes
        .as_deref()
        .map(crate::security_ledger_v7::digest::outcome);
    let resend_count = previous
        .resend_count
        .checked_add(u8::from(increment_resend))
        .ok_or(SecurityStateError::InvalidTransition)?;
    let record = MutationRecord {
        identity: previous.identity.clone(),
        client_state: state,
        runtime_disposition: runtime,
        command_ref: previous.command_ref.clone(),
        outcome_ref,
        normalized_command: previous.normalized_command.clone(),
        canonical_outcome,
        resend_count,
        recovery_summary: summary,
        created_at: previous.created_at,
        updated_at: timestamp,
    };
    validate_record(&record)?;
    transaction.execute(
        "UPDATE mutation_ledger SET client_disposition=?1,runtime_disposition=?2,canonical_outcome=?3,resend_count=?4,outcome_ref=?5,recovery_summary=?6,updated_at=?7 WHERE runtime_authority_digest=?8 AND principal_digest=?9 AND idempotency_key=?10",
        rusqlite::params![crate::security_mutation::state_name(state), runtime.map(runtime_name), outcome_bytes, i64::from(resend_count), record.outcome_ref.as_ref().map(|value| value.as_bytes().to_vec()), record.recovery_summary, timestamp, record.identity.runtime().to_vec(), record.identity.principal().to_vec(), record.identity.idempotency_key()],
    )?;
    Ok((record, true))
}
fn parse_runtime(
    value: Option<String>,
) -> Result<Option<crate::RuntimeCommitDisposition>, SecurityStateError> {
    match value.as_deref() {
        None => Ok(None),
        Some("durably_recorded") => Ok(Some(crate::RuntimeCommitDisposition::DurablyRecorded)),
        Some("not_committed_retryable") => {
            Ok(Some(crate::RuntimeCommitDisposition::NotCommittedRetryable))
        }
        Some("indeterminate") => Ok(Some(crate::RuntimeCommitDisposition::Indeterminate)),
        _ => Err(SecurityStateError::InvalidTransition),
    }
}
const fn runtime_name(value: crate::RuntimeCommitDisposition) -> &'static str {
    match value {
        crate::RuntimeCommitDisposition::DurablyRecorded => "durably_recorded",
        crate::RuntimeCommitDisposition::NotCommittedRetryable => "not_committed_retryable",
        crate::RuntimeCommitDisposition::Indeterminate => "indeterminate",
    }
}

pub(crate) struct V7RecordUpdate {
    pub(crate) state: ClientMutationDisposition,
    pub(crate) runtime: Option<crate::RuntimeCommitDisposition>,
    pub(crate) canonical_outcome: Option<crate::CanonicalMutationOutcome>,
    pub(crate) summary: String,
    pub(crate) timestamp: i64,
    pub(crate) increment_resend: bool,
}
fn validate_record(record: &MutationRecord) -> Result<(), SecurityStateError> {
    let runtime = record.runtime_disposition;
    let command = record.command_ref.is_some();
    let normalized = record.normalized_command.is_some();
    let outcome = record.outcome_ref.is_some();
    let canonical = record.canonical_outcome.is_some();
    let summary = record.recovery_summary.as_str();
    let valid = match record.client_state {
        ClientMutationDisposition::Prepared => {
            runtime.is_none()
                && command
                && normalized
                && !outcome
                && !canonical
                && record.resend_count == 0
                && summary == "prepared"
                && record.updated_at == 0
        }
        ClientMutationDisposition::Dispatching => {
            runtime.is_none() && normalized && command && !outcome && !canonical
        }
        ClientMutationDisposition::Observing => {
            matches!(
                runtime,
                None | Some(crate::RuntimeCommitDisposition::Indeterminate)
            ) && normalized
                && command
                && !outcome
                && !canonical
        }
        ClientMutationDisposition::Retryable => {
            matches!(
                runtime,
                None | Some(
                    crate::RuntimeCommitDisposition::NotCommittedRetryable
                        | crate::RuntimeCommitDisposition::Indeterminate
                )
            ) && normalized
                && command
                && !outcome
                && !canonical
                && record.resend_count <= 1
        }
        ClientMutationDisposition::Reconciling => {
            matches!(
                runtime,
                None | Some(crate::RuntimeCommitDisposition::Indeterminate)
            ) && normalized
                && command
                && !outcome
                && !canonical
        }
        ClientMutationDisposition::CanonicalOutcome => {
            runtime == Some(crate::RuntimeCommitDisposition::DurablyRecorded)
                && normalized
                && command
                && outcome
                && canonical
                && record.canonical_outcome.as_ref().is_some_and(|outcome| {
                    outcome.correlates_to_command(
                        record.normalized_command.as_ref().expect("validated"),
                    )
                })
                && !summary.is_empty()
        }
        ClientMutationDisposition::ManualResolution => {
            runtime == Some(crate::RuntimeCommitDisposition::Indeterminate)
                && !outcome
                && !canonical
                && ((normalized && command && !summary.is_empty())
                    || (!normalized
                        && !command
                        && record.resend_count == 0
                        && summary == "v6_unrecoverable"))
        }
    };
    if valid {
        Ok(())
    } else {
        Err(SecurityStateError::InvalidTransition)
    }
}
