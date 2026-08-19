use crate::{LocalStore, SecurityAnchorV1, SecurityStateError, security_state_root};
use runne_secure_store::{SecureStore, StoredSecurityAnchor};
use rusqlite::TransactionBehavior;

impl LocalStore {
    pub(crate) fn verify_anchored_admission(
        &mut self,
        secure: &dyn SecureStore,
        lock: &runne_secure_store::SecurityProfileLock<'_>,
    ) -> Result<(), SecurityStateError> {
        let context = self
            .security
            .clone()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        validate_connection_identity(&self.connection, &context)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authenticate_current_state(&transaction, secure, lock, &context)?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn authenticated_replay_read<T>(
        &mut self,
        secure: &dyn SecureStore,
        read: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, crate::ReplayStoreError>,
    ) -> Result<T, crate::ReplayStoreError> {
        let context = self
            .security
            .clone()
            .ok_or(crate::ReplayStoreError::AnchoredAdmissionRequired)?;
        if context.poisoned {
            return Err(SecurityStateError::AnchorAdvanceFailed.into());
        }
        let lock = secure
            .acquire_security_profile_lock(context.profile)
            .map_err(SecurityStateError::from)?;
        validate_connection_identity(&self.connection, &context)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authenticate_current_state(&transaction, secure, &lock, &context)?;
        let value = read(&transaction)?;
        transaction.commit()?;
        Ok(value)
    }

    /// Runs one security-sensitive SQLite mutation and advances its sealed
    /// anchor only after the database transaction is durable.
    pub(crate) fn commit_anchored_security_write<T, E>(
        &mut self,
        secure: &dyn SecureStore,
        write: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(T, bool), E>,
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
        validate_connection_identity(&self.connection, &context).map_err(E::from)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(SecurityStateError::from)
            .map_err(E::from)?;
        let anchor =
            authenticate_current_state(&transaction, secure, &lock, &context).map_err(E::from)?;
        let (value, changed) = write(&transaction)?;
        if !changed {
            transaction
                .commit()
                .map_err(SecurityStateError::from)
                .map_err(E::from)?;
            return Ok((value, anchor));
        }
        let digest = security_state_root::protected_state_root(&transaction).map_err(E::from)?;
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

fn validate_connection_identity(
    connection: &rusqlite::Connection,
    context: &crate::SecurityContext,
) -> Result<(), SecurityStateError> {
    if runne_sqlite_native_identity::opened_database_identity(connection)
        .map_err(|_| SecurityStateError::AdmissionFailed)?
        != context.file_identity
        || runne_sqlite_native_identity::path_database_identity(&context.path)
            .map_err(|_| SecurityStateError::AdmissionFailed)?
            != context.file_identity
    {
        Err(SecurityStateError::AdmissionFailed)
    } else {
        Ok(())
    }
}

fn authenticate_current_state(
    connection: &rusqlite::Connection,
    secure: &dyn SecureStore,
    lock: &runne_secure_store::SecurityProfileLock<'_>,
    context: &crate::SecurityContext,
) -> Result<SecurityAnchorV1, SecurityStateError> {
    crate::security_schema_v8::validate_v8_schema(connection)?;
    let bound: (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT profile_identity_digest,database_identity FROM security_profile WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if bound != (context.profile.to_vec(), context.database.to_vec()) {
        return Err(SecurityStateError::AnchorMismatch);
    }
    let (generation, digest): (i64, String) = connection.query_row(
        "SELECT db_generation,last_transaction_digest FROM meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let generation = u64::try_from(generation).map_err(|_| SecurityStateError::AnchorMismatch)?;
    let persisted = crate::security_recovery::verify_persisted_anchor_chain(
        connection,
        secure,
        lock,
        context.profile,
        context.database,
    )?;
    if digest != hex(&persisted.transaction_digest) || persisted.generation != generation {
        return Err(SecurityStateError::AnchorMismatch);
    }
    let StoredSecurityAnchor::V1(stored) = secure.read_security_anchor(lock)? else {
        return Err(SecurityStateError::AnchorMismatch);
    };
    if stored == persisted {
        return Ok(stored);
    }
    if generation
        == stored
            .generation
            .checked_add(1)
            .ok_or(SecurityStateError::AnchorMismatch)?
        && persisted.previous_anchor_digest == stored.digest()
    {
        secure.compare_and_advance_anchor(lock, &stored, &persisted)?;
        if secure.read_security_anchor(lock)? == StoredSecurityAnchor::V1(persisted.clone()) {
            return Ok(persisted);
        }
    }
    Err(SecurityStateError::AnchorMismatch)
}

fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
