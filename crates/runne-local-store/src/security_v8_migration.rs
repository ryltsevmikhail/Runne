use crate::{Connection, LocalStore, Path, SecurityContext, SecurityStateError};
use runne_secure_store::{SecureStore, SecurityAnchorV1, StoredSecurityAnchor};
use runne_sqlite_native_identity::{opened_database_identity, path_database_identity};

impl LocalStore {
    pub(crate) fn migrate_v8(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        previous: &SecurityAnchorV1,
    ) -> Result<Self, SecurityStateError> {
        if !lock.supports_mutation_payload_encryption() {
            return Err(runne_secure_store::SecureStoreError::Unavailable.into());
        }
        let read_only =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let identity = opened_database_identity(&read_only)
            .map_err(|_| SecurityStateError::AdmissionFailed)?;
        crate::security_schema_v8::validate_v8_schema(&read_only)?;
        let bound: (Vec<u8>, Vec<u8>) = read_only.query_row(
            "SELECT profile_identity_digest,database_identity FROM security_profile WHERE singleton=1",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let generation: i64 = read_only.query_row(
            "SELECT db_generation FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let meta_digest: String = read_only.query_row(
            "SELECT last_transaction_digest FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let persisted = crate::security_recovery::verify_persisted_anchor_chain(
            &read_only,
            secure,
            lock,
            profile,
            previous.database_identity,
        )?;
        let generation =
            u64::try_from(generation).map_err(|_| SecurityStateError::AnchorMismatch)?;
        if bound != (profile.to_vec(), previous.database_identity.to_vec())
            || meta_digest != hex(&persisted.transaction_digest)
            || path_database_identity(path).ok() != Some(identity)
        {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let current = if persisted == *previous && generation == previous.generation {
            previous.clone()
        } else if generation
            == previous
                .generation
                .checked_add(1)
                .ok_or(SecurityStateError::AnchorMismatch)?
            && persisted.generation == generation
            && persisted.previous_anchor_digest == previous.digest()
        {
            secure.compare_and_advance_anchor(lock, previous, &persisted)?;
            let advanced_anchor = secure.read_security_anchor(lock)?;
            if !matches!(&advanced_anchor, StoredSecurityAnchor::V1(anchor) if anchor == &persisted)
            {
                return Err(SecurityStateError::AnchorAdvanceFailed);
            }
            persisted
        } else {
            return Err(SecurityStateError::AnchorMismatch);
        };
        drop(read_only);
        let mut store = Self::open_admitted(path, Some(identity))?;
        store.security = Some(SecurityContext {
            profile,
            database: current.database_identity,
            path: path.to_path_buf(),
            file_identity: opened_database_identity(&store.connection)
                .map_err(|_| SecurityStateError::AdmissionFailed)?,
            poisoned: false,
        });
        store
            .connection
            .pragma_update(None, "secure_delete", "ON")?;
        let migration_context = store
            .security
            .clone()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        let ((), encrypted_anchor) = store.commit_anchored_security_write_under_lock(
            secure,
            lock,
            |transaction, lock| {
                crate::security_schema_v8::validate_v8_schema(transaction)?;
                let changed = crate::security_v8_payload_migration::reencrypt_v8_payloads(
                    transaction,
                    lock,
                    migration_context.profile,
                    migration_context.database,
                )?;
                Ok::<_, SecurityStateError>(((), changed))
            },
        )?;
        store.scrub_v8_payload_remnants()?;
        store.verify_anchored_admission(secure, lock)?;
        #[cfg(feature = "test-support")]
        if crate::security_open_test_support_v8::fail_after_v8_payload_scrub_for_test() {
            return Err(SecurityStateError::AdmissionFailed);
        }
        store.finish_v8_payload_migration(secure, lock, &encrypted_anchor)?;
        Ok(store)
    }

    fn finish_v8_payload_migration(
        &mut self,
        secure: &dyn SecureStore,
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        encrypted_anchor: &SecurityAnchorV1,
    ) -> Result<(), SecurityStateError> {
        let next = self.migrate_v8_to_v9(secure, lock, encrypted_anchor)?;
        secure.compare_and_advance_anchor(lock, encrypted_anchor, &next)?;
        if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(next) {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        self.verify_anchored_admission(secure, lock)
    }

    fn migrate_v8_to_v9(
        &mut self,
        secure: &dyn SecureStore,
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        previous: &SecurityAnchorV1,
    ) -> Result<SecurityAnchorV1, SecurityStateError> {
        let context = self
            .security
            .clone()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        crate::security_schema_v8::validate_v8_schema(&transaction)?;
        let bound: (Vec<u8>, Vec<u8>) = transaction.query_row(
            "SELECT profile_identity_digest,database_identity FROM security_profile WHERE singleton=1",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let persisted = crate::security_recovery::verify_persisted_anchor_chain(
            &transaction,
            secure,
            lock,
            context.profile,
            context.database,
        )?;
        let generation: i64 = transaction.query_row(
            "SELECT db_generation FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let meta_digest: String = transaction.query_row(
            "SELECT last_transaction_digest FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if bound != (context.profile.to_vec(), context.database.to_vec())
            || u64::try_from(generation).ok() != Some(previous.generation)
            || persisted != *previous
            || meta_digest != hex(&persisted.transaction_digest)
            || crate::security_state_root::protected_state_root(&transaction)?
                != previous.transaction_digest
        {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(SecurityStateError::InvalidTransition)?;
        transaction.pragma_update(None, "user_version", 9_i64)?;
        transaction.execute(
            "UPDATE meta SET schema_version=9,db_generation=?1,commit_marker=1 WHERE singleton=1",
            [i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?],
        )?;
        let digest = crate::security_state_root::protected_state_root(&transaction)?;
        let seal = secure.seal_security_transaction(
            lock,
            context.database,
            generation,
            digest,
            previous.digest(),
        )?;
        let next = SecurityAnchorV1::new(
            context.profile,
            context.database,
            generation,
            digest,
            previous.digest(),
            seal,
        )?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
            rusqlite::params![
                i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,
                digest.to_vec(),
                previous.digest().to_vec(),
                next.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute(
            "UPDATE meta SET last_transaction_digest=?1 WHERE singleton=1",
            [hex(&next.transaction_digest)],
        )?;
        transaction.commit()?;
        Ok(next)
    }

    fn scrub_v8_payload_remnants(&self) -> Result<(), SecurityStateError> {
        let context = self
            .security
            .as_ref()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        if opened_database_identity(&self.connection)
            .map_err(|_| SecurityStateError::AdmissionFailed)?
            != context.file_identity
            || path_database_identity(&context.path)
                .map_err(|_| SecurityStateError::AdmissionFailed)?
                != context.file_identity
        {
            return Err(SecurityStateError::AdmissionFailed);
        }
        self.connection.execute_batch("VACUUM;")?;
        if opened_database_identity(&self.connection)
            .map_err(|_| SecurityStateError::AdmissionFailed)?
            != context.file_identity
            || path_database_identity(&context.path)
                .map_err(|_| SecurityStateError::AdmissionFailed)?
                != context.file_identity
        {
            return Err(SecurityStateError::AdmissionFailed);
        }
        let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        if (busy, log_frames, checkpointed_frames) != (0, 0, 0) {
            return Err(SecurityStateError::AdmissionFailed);
        }
        Ok(())
    }
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
