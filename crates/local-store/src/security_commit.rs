use crate::{LocalStore, SecurityAnchorV1, SecurityStateError};
use gocode_secure_store::{SecureStore, StoredSecurityAnchor};
use rusqlite::TransactionBehavior;

impl LocalStore {
    /// Runs one security-sensitive SQLite mutation and advances its sealed
    /// anchor only after the database transaction is durable.
    pub(crate) fn commit_anchored_security_write<T, E>(
        &mut self,
        secure: &dyn SecureStore,
        write: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(T, Option<[u8; 32]>), E>,
    ) -> Result<(T, SecurityAnchorV1), E>
    where
        E: From<SecurityStateError>,
    {
        let context = self
            .security
            .clone()
            .ok_or_else(|| E::from(SecurityStateError::AdmissionFailed))?;
        if context.poisoned {
            return Err(E::from(SecurityStateError::AnchorAdvanceFailed));
        }
        let lock = secure
            .acquire_security_profile_lock(context.profile)
            .map_err(SecurityStateError::from)
            .map_err(E::from)?;
        let StoredSecurityAnchor::V1(anchor) = secure
            .read_security_anchor(&lock)
            .map_err(SecurityStateError::from)
            .map_err(E::from)?
        else {
            return Err(E::from(SecurityStateError::AnchorMismatch));
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(SecurityStateError::from)
            .map_err(E::from)?;
        let (value, digest) = write(&transaction)?;
        let Some(digest) = digest else {
            transaction
                .commit()
                .map_err(SecurityStateError::from)
                .map_err(E::from)?;
            return Ok((value, anchor));
        };
        let generation = anchor
            .generation
            .checked_add(1)
            .ok_or_else(|| E::from(SecurityStateError::InvalidTransition))?;
        let seal = secure
            .seal_security_transaction(&lock, context.database, generation, digest, anchor.digest())
            .map_err(SecurityStateError::from)
            .map_err(E::from)?;
        let next = SecurityAnchorV1::new(
            context.profile,
            context.database,
            generation,
            digest,
            anchor.digest(),
            seal,
        )
        .map_err(SecurityStateError::from)
        .map_err(E::from)?;
        transaction
            .execute(
                "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
                rusqlite::params![
                    i64::try_from(generation)
                        .map_err(|_| SecurityStateError::InvalidTransition)
                        .map_err(E::from)?,
                    digest.to_vec(),
                    anchor.digest().to_vec(),
                    next.sealed_transaction.as_bytes(),
                ],
            )
            .map_err(SecurityStateError::from)
            .map_err(E::from)?;
        transaction
            .execute(
                "UPDATE meta SET db_generation=?1,last_transaction_digest=?2,commit_marker=1 WHERE singleton=1",
                rusqlite::params![
                    i64::try_from(generation)
                        .map_err(|_| SecurityStateError::InvalidTransition)
                        .map_err(E::from)?,
                    hex(&digest),
                ],
            )
            .map_err(SecurityStateError::from)
            .map_err(E::from)?;
        transaction
            .commit()
            .map_err(SecurityStateError::from)
            .map_err(E::from)?;
        if secure
            .compare_and_advance_anchor(&lock, &anchor, &next)
            .is_err()
            || secure.read_security_anchor(&lock).ok().as_ref()
                != Some(&StoredSecurityAnchor::V1(next.clone()))
        {
            self.security.as_mut().expect("anchored").poisoned = true;
            return Err(E::from(SecurityStateError::AnchorAdvanceFailed));
        }
        Ok((value, next))
    }
}

fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
