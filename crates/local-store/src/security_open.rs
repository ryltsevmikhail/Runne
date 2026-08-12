use crate::{
    Connection, Digest, LocalStore, Path, SecurityContext, SecurityStateError, Sha256,
    TransactionBehavior,
};
use gocode_secure_store::{SecureStore, SecurityAnchorV1, StoredSecurityAnchor};

impl LocalStore {
    pub fn open_anchored(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
    ) -> Result<Self, SecurityStateError> {
        let absent = std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        let lock = secure.acquire_security_profile_lock(profile)?;
        let stored = secure.read_security_anchor(&lock)?;
        if !absent {
            return match stored {
                StoredSecurityAnchor::LegacyGeneration(_) => {
                    Self::migrate_legacy(path, secure, profile, &lock, stored)
                }
                StoredSecurityAnchor::V1(anchor) => {
                    Self::reopen_v1(path, secure, profile, &lock, anchor)
                }
                StoredSecurityAnchor::Missing => Err(SecurityStateError::AnchorMismatch),
            };
        }
        if stored != StoredSecurityAnchor::Missing {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let mut store = Self::open(path).map_err(SecurityStateError::Open)?;
        let database = database_identity(path)?;
        let digest = digest(b"gocode/security/genesis/v1\0", &database);
        let seal = secure.seal_security_transaction(&lock, database, 1, digest, [0; 32])?;
        let anchor = SecurityAnchorV1::new(profile, database, 1, digest, [0; 32], seal)?;
        store.install_security_root(&anchor)?;
        secure.initialize_security_anchor(&lock, &anchor)?;
        if secure.read_security_anchor(&lock)? != StoredSecurityAnchor::V1(anchor.clone()) {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        store.security = Some(SecurityContext {
            profile,
            database,
            poisoned: false,
        });
        Ok(store)
    }

    fn reopen_v1(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
        lock: &gocode_secure_store::SecurityProfileLock<'_>,
        anchor: SecurityAnchorV1,
    ) -> Result<Self, SecurityStateError> {
        if anchor.profile_identity_digest != profile {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let read_only =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        crate::security_schema_v6::validate_v6_schema(&read_only)?;
        let bound: (Vec<u8>, Vec<u8>) = read_only.query_row("SELECT profile_identity_digest, database_identity FROM security_profile WHERE singleton=1", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
        if bound != (profile.to_vec(), anchor.database_identity.to_vec()) {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let database_generation: i64 = read_only.query_row(
            "SELECT db_generation FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let database_generation =
            u64::try_from(database_generation).map_err(|_| SecurityStateError::AnchorMismatch)?;
        let persisted = crate::security_recovery::verify_persisted_anchor_chain(
            &read_only,
            secure,
            lock,
            profile,
            anchor.database_identity,
        )?;
        let meta_digest: String = read_only.query_row(
            "SELECT last_transaction_digest FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if meta_digest != hex(&persisted.transaction_digest) {
            return Err(SecurityStateError::AnchorMismatch);
        }
        if database_generation == anchor.generation && persisted != anchor {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let one_ahead = database_generation
            == anchor
                .generation
                .checked_add(1)
                .ok_or(SecurityStateError::AnchorMismatch)?
            && persisted.previous_anchor_digest == anchor.digest()
            && persisted.generation == database_generation;
        if !one_ahead && database_generation != anchor.generation {
            return Err(SecurityStateError::AnchorMismatch);
        }
        drop(read_only);
        if one_ahead {
            secure.compare_and_advance_anchor(lock, &anchor, &persisted)?;
            if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(persisted.clone()) {
                return Err(SecurityStateError::AnchorAdvanceFailed);
            }
        }
        let mut store = Self::open_admitted(path)?;
        store.security = Some(SecurityContext {
            profile,
            database: anchor.database_identity,
            poisoned: false,
        });
        Ok(store)
    }

    fn open_admitted(path: &Path) -> Result<Self, SecurityStateError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        Ok(Self {
            connection,
            security: None,
        })
    }

    fn migrate_legacy(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
        lock: &gocode_secure_store::SecurityProfileLock<'_>,
        stored: StoredSecurityAnchor,
    ) -> Result<Self, SecurityStateError> {
        let StoredSecurityAnchor::LegacyGeneration(generation) = stored else {
            return Err(SecurityStateError::AdmissionFailed);
        };
        let read_only =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        crate::recent_root_schema::validate_v5_schema(&read_only)
            .map_err(SecurityStateError::Open)?;
        let database_generation: i64 = read_only.query_row(
            "SELECT db_generation FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let rows: i64 =
            read_only.query_row("SELECT COUNT(*) FROM mutation_ledger", [], |row| row.get(0))?;
        if u64::try_from(database_generation).ok() != Some(generation) || rows != 0 {
            return Err(SecurityStateError::AdmissionFailed);
        }
        drop(read_only);
        let mut store = Self::open(path).map_err(SecurityStateError::Open)?;
        let database = database_identity(path)?;
        let next = generation
            .checked_add(1)
            .ok_or(SecurityStateError::InvalidTransition)?;
        let previous = digest(
            b"gocode/security/legacy-anchor/v1\0",
            &generation.to_be_bytes(),
        );
        let transaction_digest = digest(b"gocode/security/v6-migration/v1\0", &database);
        let seal =
            secure.seal_security_transaction(lock, database, next, transaction_digest, previous)?;
        let anchor =
            SecurityAnchorV1::new(profile, database, next, transaction_digest, previous, seal)?;
        store.install_v6_migration(&anchor)?;
        secure.compare_and_migrate_legacy_anchor(lock, generation, &anchor)?;
        if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(anchor.clone()) {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        store.security = Some(SecurityContext {
            profile,
            database,
            poisoned: false,
        });
        Ok(store)
    }

    fn install_security_root(
        &mut self,
        anchor: &SecurityAnchorV1,
    ) -> Result<(), SecurityStateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(&format!(
            "DROP TABLE mutation_ledger; {}; {}; {}; PRAGMA user_version=6;",
            crate::security_schema_v6::LEDGER_SQL,
            crate::security_schema_v6::TRANSACTIONS_SQL,
            crate::security_schema_v6::PROFILE_SQL
        ))?;
        transaction.execute(
            "INSERT INTO security_profile VALUES (1, ?1, ?2)",
            rusqlite::params![
                anchor.profile_identity_digest.to_vec(),
                anchor.database_identity.to_vec()
            ],
        )?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1, ?2, ?3, ?4, 1)",
            rusqlite::params![
                1_i64,
                anchor.transaction_digest.to_vec(),
                anchor.previous_anchor_digest.to_vec(),
                anchor.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute("UPDATE meta SET schema_version = 6, last_transaction_digest = ?1, commit_marker = 1 WHERE singleton = 1", [hex(&anchor.transaction_digest)])?;
        transaction.commit()?;
        Ok(())
    }

    fn install_v6_migration(
        &mut self,
        anchor: &SecurityAnchorV1,
    ) -> Result<(), SecurityStateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(&format!(
            "DROP TABLE mutation_ledger; {}; {}; {}; PRAGMA user_version=6;",
            crate::security_schema_v6::LEDGER_SQL,
            crate::security_schema_v6::TRANSACTIONS_SQL,
            crate::security_schema_v6::PROFILE_SQL
        ))?;
        transaction.execute(
            "INSERT INTO security_profile VALUES (1, ?1, ?2)",
            rusqlite::params![
                anchor.profile_identity_digest.to_vec(),
                anchor.database_identity.to_vec()
            ],
        )?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1, ?2, ?3, ?4, 1)",
            rusqlite::params![
                i64::try_from(anchor.generation)
                    .map_err(|_| SecurityStateError::InvalidTransition)?,
                anchor.transaction_digest.to_vec(),
                anchor.previous_anchor_digest.to_vec(),
                anchor.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute("UPDATE meta SET schema_version=6, db_generation=?1, last_transaction_digest=?2, commit_marker=1 WHERE singleton=1", rusqlite::params![i64::try_from(anchor.generation).map_err(|_| SecurityStateError::InvalidTransition)?, hex(&anchor.transaction_digest)])?;
        transaction.commit()?;
        Ok(())
    }
}

fn database_identity(path: &Path) -> Result<[u8; 32], SecurityStateError> {
    Ok(digest(
        b"gocode/security/database-identity/v1\0",
        path.canonicalize()
            .map_err(|_| SecurityStateError::AdmissionFailed)?
            .to_string_lossy()
            .as_bytes(),
    ))
}
fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}
fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
