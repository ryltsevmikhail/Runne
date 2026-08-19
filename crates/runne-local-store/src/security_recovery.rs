use crate::{Connection, SecurityStateError};
use runne_secure_store::{
    SealedTransactionTag, SecureStore, SecurityAnchorV1, SecurityProfileLock,
};

pub(crate) fn verify_persisted_anchor_chain(
    connection: &Connection,
    secure: &dyn SecureStore,
    lock: &SecurityProfileLock<'_>,
    profile: [u8; 32],
    database: [u8; 32],
) -> Result<SecurityAnchorV1, SecurityStateError> {
    let mut statement = connection.prepare(
        "SELECT generation,transaction_digest,previous_anchor_digest,sealed_transaction FROM security_transactions ORDER BY generation",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut previous: Option<SecurityAnchorV1> = None;
    for (generation, digest, predecessor, seal) in rows {
        let generation =
            u64::try_from(generation).map_err(|_| SecurityStateError::AnchorMismatch)?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| SecurityStateError::AnchorMismatch)?;
        let predecessor: [u8; 32] = predecessor
            .try_into()
            .map_err(|_| SecurityStateError::AnchorMismatch)?;
        let anchor = SecurityAnchorV1::new(
            profile,
            database,
            generation,
            digest,
            predecessor,
            SealedTransactionTag::from_storage(seal)?,
        )?;
        if let Some(last) = &previous
            && (last.generation.checked_add(1) != Some(anchor.generation)
                || anchor.previous_anchor_digest != last.digest())
        {
            return Err(SecurityStateError::AnchorMismatch);
        }
        secure.verify_security_transaction(lock, &anchor)?;
        previous = Some(anchor);
    }
    let latest = previous.ok_or(SecurityStateError::AnchorMismatch)?;
    if crate::security_state_root::protected_state_root(connection)? != latest.transaction_digest {
        return Err(SecurityStateError::AnchorMismatch);
    }
    Ok(latest)
}
