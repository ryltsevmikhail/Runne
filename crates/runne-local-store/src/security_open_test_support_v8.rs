use crate::{LocalStore, SecurityStateError};
use std::cell::Cell;

thread_local! {
    static FAIL_AFTER_V8_PAYLOAD_SCRUB: Cell<bool> = const { Cell::new(false) };
}

/// Interrupts one synthetic v8 migration after payload scrubbing and before
/// the schema-v9 fence is committed.
pub fn fail_after_v8_payload_scrub_once_for_test() {
    FAIL_AFTER_V8_PAYLOAD_SCRUB.with(|fail| fail.set(true));
}

pub fn fail_after_v8_payload_scrub_for_test() -> bool {
    FAIL_AFTER_V8_PAYLOAD_SCRUB.with(|fail| fail.replace(false))
}

/// Seals the current fixture as a legacy V8 writer image for migration tests.
///
/// # Errors
///
/// Returns an error when the fixture cannot be authenticated or resealed.
pub fn downgrade_to_v8_for_test(
    store: &mut LocalStore,
    secure: &dyn runne_secure_store::SecureStore,
    mutate_sql: &str,
) -> Result<(), SecurityStateError> {
    let context = store
        .security
        .clone()
        .ok_or(SecurityStateError::AdmissionFailed)?;
    let lock = secure.acquire_security_profile_lock(context.profile)?;
    let current = crate::security_recovery::verify_persisted_anchor_chain(
        &store.connection,
        secure,
        &lock,
        context.profile,
        context.database,
    )?;
    let transaction = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "user_version", 8_i64)?;
    transaction.execute("UPDATE meta SET schema_version=8 WHERE singleton=1", [])?;
    transaction.execute_batch(mutate_sql)?;
    let generation = current
        .generation
        .checked_add(1)
        .ok_or(SecurityStateError::InvalidTransition)?;
    let digest = crate::security_state_root::protected_state_root(&transaction)?;
    let seal = secure.seal_security_transaction(
        &lock,
        context.database,
        generation,
        digest,
        current.digest(),
    )?;
    let next = runne_secure_store::SecurityAnchorV1::new(
        context.profile,
        context.database,
        generation,
        digest,
        current.digest(),
        seal,
    )?;
    transaction.execute(
        "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
        rusqlite::params![
            i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,
            digest.to_vec(),
            current.digest().to_vec(),
            next.sealed_transaction.as_bytes()
        ],
    )?;
    transaction.execute("UPDATE meta SET db_generation=?1,last_transaction_digest=?2,commit_marker=1 WHERE singleton=1", rusqlite::params![i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,hex(&digest)])?;
    transaction.commit()?;
    secure.compare_and_advance_anchor(&lock, &current, &next)?;
    Ok(())
}

fn hex(value: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    value
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String is infallible");
            output
        })
}
