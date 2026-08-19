use crate::security_open_hash::{database_identity, digest, hex};
use crate::{Connection, LocalStore, Path, SecurityContext, SecurityStateError};
use runne_secure_store::{SecureStore, SecurityAnchorV1, StoredSecurityAnchor};
use runne_sqlite_native_identity::{
    DatabaseFileIdentity, opened_database_identity, path_database_identity,
};
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
                    let mut store = Self::reopen_v1(path, secure, profile, &lock, anchor)?;
                    drop(lock);
                    store
                        .recover_anchored_pending_promotions(secure)
                        .map_err(|_| SecurityStateError::AdmissionFailed)?;
                    Ok(store)
                }
                StoredSecurityAnchor::Missing => Err(SecurityStateError::AnchorMismatch),
            };
        }
        if stored != StoredSecurityAnchor::Missing {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let mut store = Self::open(path).map_err(SecurityStateError::Open)?;
        let file_identity =
            path_database_identity(path).map_err(|_| SecurityStateError::AdmissionFailed)?;
        if opened_database_identity(&store.connection)
            .map_err(|_| SecurityStateError::AdmissionFailed)?
            != file_identity
        {
            return Err(SecurityStateError::AdmissionFailed);
        }
        let database = database_identity(path)?;
        let digest = crate::security_state_root::empty_protected_state_root();
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
            path: path.to_path_buf(),
            file_identity,
            poisoned: false,
        });
        Ok(store)
    }

    fn reopen_v1(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        anchor: SecurityAnchorV1,
    ) -> Result<Self, SecurityStateError> {
        if anchor.profile_identity_digest != profile {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let read_only =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let read_only_identity = opened_database_identity(&read_only)
            .map_err(|_| SecurityStateError::AdmissionFailed)?;
        let version: i64 = read_only.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 6 {
            drop(read_only);
            return Self::migrate_v6(path, secure, profile, lock, &anchor);
        }
        if version == 7 {
            drop(read_only);
            return Self::migrate_v7(path, secure, profile, lock, &anchor);
        }
        crate::security_schema_v8::validate_v8_schema(&read_only)?;
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
        if path_database_identity(path).ok() != Some(read_only_identity) {
            return Err(SecurityStateError::AdmissionFailed);
        }
        drop(read_only);
        if one_ahead {
            secure.compare_and_advance_anchor(lock, &anchor, &persisted)?;
            if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(persisted.clone()) {
                return Err(SecurityStateError::AnchorAdvanceFailed);
            }
        }
        let mut store = Self::open_admitted(path, Some(read_only_identity))?;
        store.security = Some(SecurityContext {
            profile,
            database: anchor.database_identity,
            path: path.to_path_buf(),
            file_identity: opened_database_identity(&store.connection)
                .map_err(|_| SecurityStateError::AdmissionFailed)?,
            poisoned: false,
        });
        store.verify_anchored_admission(secure, lock)?;
        Ok(store)
    }

    pub(crate) fn open_admitted(
        path: &Path,
        expected: Option<DatabaseFileIdentity>,
    ) -> Result<Self, SecurityStateError> {
        #[cfg(feature = "test-support")]
        crate::security_open_test_support::before_admitted_open();
        let opened = Connection::open(path);
        #[cfg(feature = "test-support")]
        crate::security_open_test_support::after_admitted_open();
        let connection = opened?;
        if expected.is_some_and(|identity| {
            path_database_identity(path).ok() != Some(identity)
                || opened_database_identity(&connection).ok() != Some(identity)
        }) {
            return Err(SecurityStateError::AdmissionFailed);
        }
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        Ok(Self {
            connection,
            security: None,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn migrate_legacy(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        stored: StoredSecurityAnchor,
    ) -> Result<Self, SecurityStateError> {
        let StoredSecurityAnchor::LegacyGeneration(generation) = stored else {
            return Err(SecurityStateError::AdmissionFailed);
        };
        let read_only =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let read_only_identity = opened_database_identity(&read_only)
            .map_err(|_| SecurityStateError::AdmissionFailed)?;
        let version: i64 = read_only.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 7 {
            drop(read_only);
            return Self::resume_legacy_v7(path, secure, profile, lock, generation);
        }
        if version == 6 {
            let database = database_identity(path)?;
            crate::security_schema_v6::validate_v6_schema(&read_only)?;
            let bound: (Vec<u8>, Vec<u8>) = read_only.query_row("SELECT profile_identity_digest,database_identity FROM security_profile WHERE singleton=1", [], |row| Ok((row.get(0)?,row.get(1)?)))?;
            let persisted = crate::security_recovery::verify_persisted_anchor_chain(
                &read_only, secure, lock, profile, database,
            )?;
            let db_generation: i64 = read_only.query_row(
                "SELECT db_generation FROM meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            let meta_digest: String = read_only.query_row(
                "SELECT last_transaction_digest FROM meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            if bound != (profile.to_vec(), database.to_vec())
                || u64::try_from(db_generation).ok()
                    != Some(
                        generation
                            .checked_add(1)
                            .ok_or(SecurityStateError::InvalidTransition)?,
                    )
                || persisted.generation
                    != generation
                        .checked_add(1)
                        .ok_or(SecurityStateError::InvalidTransition)?
                || persisted.previous_anchor_digest
                    != digest(
                        b"runne/security/legacy-anchor/v1\0",
                        &generation.to_be_bytes(),
                    )
                || meta_digest != hex(&persisted.transaction_digest)
            {
                return Err(SecurityStateError::AnchorMismatch);
            }
            if path_database_identity(path).ok() != Some(read_only_identity) {
                return Err(SecurityStateError::AdmissionFailed);
            }
            drop(read_only);
            secure.compare_and_migrate_legacy_anchor(lock, generation, &persisted)?;
            if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(persisted.clone()) {
                return Err(SecurityStateError::AnchorAdvanceFailed);
            }
            let mut store = Self::open_admitted(path, Some(read_only_identity))?;
            store.security = Some(SecurityContext {
                profile,
                database,
                path: path.to_path_buf(),
                file_identity: opened_database_identity(&store.connection)
                    .map_err(|_| SecurityStateError::AdmissionFailed)?,
                poisoned: false,
            });
            store.verify_anchored_admission(secure, lock)?;
            return Ok(store);
        }
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
        if path_database_identity(path).ok() != Some(read_only_identity) {
            return Err(SecurityStateError::AdmissionFailed);
        }
        drop(read_only);
        let mut store = Self::open(path).map_err(SecurityStateError::Open)?;
        if path_database_identity(path).map_err(|_| SecurityStateError::AdmissionFailed)?
            != read_only_identity
            || opened_database_identity(&store.connection)
                .map_err(|_| SecurityStateError::AdmissionFailed)?
                != read_only_identity
        {
            return Err(SecurityStateError::AdmissionFailed);
        }
        let database = database_identity(path)?;
        let next = generation
            .checked_add(1)
            .ok_or(SecurityStateError::InvalidTransition)?;
        let previous = digest(
            b"runne/security/legacy-anchor/v1\0",
            &generation.to_be_bytes(),
        );
        let anchor = store.install_v7_migration(secure, lock, profile, database, next, previous)?;
        secure.compare_and_migrate_legacy_anchor(lock, generation, &anchor)?;
        if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(anchor.clone()) {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        store.security = Some(SecurityContext {
            profile,
            database,
            path: path.to_path_buf(),
            file_identity: opened_database_identity(&store.connection)
                .map_err(|_| SecurityStateError::AdmissionFailed)?,
            poisoned: false,
        });
        Ok(store)
    }
}
