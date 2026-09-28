use crate::{BoundedCanonicalId, CommandRef, MutationIdentity, OutcomeRef, SecurityStateError};
use runne_secure_store::SecurityProfileLock;

const ENVELOPE_MAGIC: &[u8; 4] = b"RNV9";

pub fn reencrypt_v8_payloads(
    connection: &rusqlite::Transaction<'_>,
    lock: &SecurityProfileLock<'_>,
    profile: [u8; 32],
    database: [u8; 32],
) -> Result<bool, SecurityStateError> {
    let mut statement = connection.prepare(
        "SELECT runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,
                idempotency_key,expected_version,semantic_digest,normalized_command,
                canonical_outcome,command_ref,outcome_ref
         FROM mutation_ledger ORDER BY runtime_authority_digest,principal_digest,idempotency_key",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(RawPayloadRow {
                runtime: row.get(0)?,
                principal: row.get(1)?,
                operation: row.get(2)?,
                target_kind: row.get(3)?,
                target: row.get(4)?,
                idempotency_key: row.get(5)?,
                expected_version: row.get(6)?,
                semantic_digest: row.get(7)?,
                command: row.get(8)?,
                outcome: row.get(9)?,
                command_ref: row.get(10)?,
                outcome_ref: row.get(11)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    let mut changed = false;
    for row in rows {
        let identity = identity(&row)?;
        // Decode and validate the entire authenticated logical record before
        // any legacy bytes are replaced.
        crate::security_record::load_record(connection, identity.clone(), lock, profile, database)?
            .ok_or(SecurityStateError::IdentityConflict)?;

        let command = encrypt_legacy(
            lock,
            profile,
            database,
            &identity,
            crate::security_mutation_payload::PayloadKind::Command,
            row.command,
            row.command_ref,
        )?;
        let outcome = encrypt_legacy(
            lock,
            profile,
            database,
            &identity,
            crate::security_mutation_payload::PayloadKind::Outcome,
            row.outcome,
            row.outcome_ref,
        )?;
        if command.is_some() || outcome.is_some() {
            connection.execute(
                "UPDATE mutation_ledger
                 SET normalized_command=COALESCE(?1,normalized_command),
                     canonical_outcome=COALESCE(?2,canonical_outcome)
                 WHERE runtime_authority_digest=?3 AND principal_digest=?4 AND idempotency_key=?5",
                rusqlite::params![
                    command,
                    outcome,
                    identity.runtime().to_vec(),
                    identity.principal().to_vec(),
                    identity.idempotency_key(),
                ],
            )?;
            changed = true;
        }
    }
    Ok(changed)
}

fn encrypt_legacy(
    lock: &SecurityProfileLock<'_>,
    profile: [u8; 32],
    database: [u8; 32],
    identity: &MutationIdentity,
    kind: crate::security_mutation_payload::PayloadKind,
    bytes: Option<Vec<u8>>,
    reference: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, SecurityStateError> {
    let Some(bytes) = bytes else {
        if reference.is_some() {
            return Err(SecurityStateError::IdentityConflict);
        }
        return Ok(None);
    };
    let reference: [u8; 32] = reference
        .ok_or(SecurityStateError::IdentityConflict)?
        .try_into()
        .map_err(|_| SecurityStateError::IdentityConflict)?;
    let expected = match kind {
        crate::security_mutation_payload::PayloadKind::Command => {
            CommandRef::new(reference).map(|value| *value.as_bytes())
        }
        crate::security_mutation_payload::PayloadKind::Outcome => {
            OutcomeRef::new(reference).map(|value| *value.as_bytes())
        }
    }?;
    let plaintext = crate::security_mutation_payload::open(
        lock, profile, database, identity, kind, &bytes, &expected,
    )?;
    if bytes.starts_with(ENVELOPE_MAGIC) {
        return Ok(None);
    }
    crate::security_mutation_payload::seal(lock, profile, database, identity, kind, &plaintext)
        .map(Some)
}

struct RawPayloadRow {
    runtime: Vec<u8>,
    principal: Vec<u8>,
    operation: String,
    target_kind: String,
    target: Vec<u8>,
    idempotency_key: String,
    expected_version: i64,
    semantic_digest: Vec<u8>,
    command: Option<Vec<u8>>,
    outcome: Option<Vec<u8>>,
    command_ref: Option<Vec<u8>>,
    outcome_ref: Option<Vec<u8>>,
}

fn identity(row: &RawPayloadRow) -> Result<MutationIdentity, SecurityStateError> {
    MutationIdentity::new(
        row.runtime
            .clone()
            .try_into()
            .map_err(|_| SecurityStateError::IdentityConflict)?,
        row.principal
            .clone()
            .try_into()
            .map_err(|_| SecurityStateError::IdentityConflict)?,
        crate::security_recovery_read::operation_from_name(&row.operation)?,
        crate::security_recovery_read::target_from_name(&row.target_kind)?,
        BoundedCanonicalId::parse(&row.target)?,
        row.idempotency_key.clone(),
        u64::try_from(row.expected_version).map_err(|_| SecurityStateError::IdentityConflict)?,
        row.semantic_digest
            .clone()
            .try_into()
            .map_err(|_| SecurityStateError::IdentityConflict)?,
    )
}
