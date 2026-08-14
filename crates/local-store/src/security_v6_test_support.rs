use crate::{LocalStore, SecurityStateError};
use gocode_secure_store::SecureStore;

const V6_PROJECT_ID: &[u8] = b"018f2e3a-7000-7000-8000-000000000096";

/// # Errors
///
/// Returns an error when the current anchored state cannot be converted into
/// the test-only sealed v6 witness.
pub fn downgrade_with_active_rows(
    store: &mut LocalStore,
    secure: &dyn SecureStore,
) -> Result<Vec<String>, SecurityStateError> {
    let context = store
        .security
        .as_ref()
        .ok_or(SecurityStateError::AdmissionFailed)?
        .clone();
    let lock = secure.acquire_security_profile_lock(context.profile)?;
    let anchor = crate::security_recovery::verify_persisted_anchor_chain(
        &store.connection,
        secure,
        &lock,
        context.profile,
        context.database,
    )?;
    let keys = ["prepared", "dispatching", "retryable", "canonical"];
    let transaction = store.connection.transaction()?;
    transaction.execute_batch(&format!(
        "DROP TABLE replay_promotion_pending; DROP TABLE replay_active_generations; DROP TABLE replay_shadow_events; DROP TABLE replay_shadow_generations; ALTER TABLE mutation_ledger RENAME TO mutation_ledger_v7; {}; INSERT INTO mutation_ledger (runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest,client_disposition,runtime_disposition,command_ref,outcome_ref,recovery_summary,created_at,updated_at) SELECT runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest,CASE rowid WHEN 1 THEN 'prepared' WHEN 2 THEN 'dispatching' WHEN 3 THEN 'retryable' ELSE 'canonical_outcome' END,NULL,NULL,NULL,'legacy',0,0 FROM mutation_ledger_v7; DROP TABLE mutation_ledger_v7; PRAGMA user_version=6; UPDATE meta SET schema_version=6;",
        crate::security_schema_v6::LEDGER_SQL,
    ))?;
    for key in keys {
        transaction.execute(
            "INSERT INTO mutation_ledger VALUES (?1,?2,'project_create','project',?3,?4,0,?5,'prepared',NULL,NULL,NULL,'legacy',0,0)",
            rusqlite::params![[1_u8; 32].to_vec(), [2_u8; 32].to_vec(), V6_PROJECT_ID.to_vec(), key, [3_u8; 32].to_vec()],
        )?;
    }
    transaction.execute("DELETE FROM security_transactions", [])?;
    let digest = v6_root(&transaction)?;
    let generation = anchor
        .generation
        .checked_add(1)
        .ok_or(SecurityStateError::InvalidTransition)?;
    let seal = secure.seal_security_transaction(
        &lock,
        context.database,
        generation,
        digest,
        anchor.digest(),
    )?;
    let next = gocode_secure_store::SecurityAnchorV1::new(
        context.profile,
        context.database,
        generation,
        digest,
        anchor.digest(),
        seal,
    )?;
    transaction.execute(
        "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
        rusqlite::params![
            i64::try_from(next.generation).map_err(|_| SecurityStateError::InvalidTransition)?,
            digest.to_vec(),
            next.previous_anchor_digest.to_vec(),
            next.sealed_transaction.as_bytes()
        ],
    )?;
    transaction.execute(
        "UPDATE meta SET db_generation=?1,last_transaction_digest=?2",
        rusqlite::params![
            i64::try_from(next.generation).map_err(|_| SecurityStateError::InvalidTransition)?,
            hex(&digest)
        ],
    )?;
    transaction.commit()?;
    secure.compare_and_advance_anchor(&lock, &anchor, &next)?;
    Ok(keys.map(str::to_owned).to_vec())
}

fn v6_root(connection: &rusqlite::Connection) -> Result<[u8; 32], SecurityStateError> {
    crate::security_state_root::protected_state_root(connection)
}
fn hex(value: &[u8; 32]) -> String {
    use std::fmt::Write;
    value
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        })
}
