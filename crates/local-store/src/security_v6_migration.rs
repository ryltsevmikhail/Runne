use crate::{Connection, LocalStore, Path, SecurityContext, SecurityStateError};
use gocode_secure_store::{SecureStore, SecurityAnchorV1, StoredSecurityAnchor};

impl LocalStore {
    pub(crate) fn migrate_v7(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
        lock: &gocode_secure_store::SecurityProfileLock<'_>,
        anchor: &SecurityAnchorV1,
    ) -> Result<Self, SecurityStateError> {
        let read_only =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let identity = gocode_sqlite_native_identity::opened_database_identity(&read_only)
            .map_err(|_| SecurityStateError::AdmissionFailed)?;
        crate::security_schema_v7::validate_v7_schema(&read_only)?;
        let persisted = crate::security_recovery::verify_persisted_anchor_chain(
            &read_only,
            secure,
            lock,
            profile,
            anchor.database_identity,
        )?;
        if persisted != *anchor
            || gocode_sqlite_native_identity::path_database_identity(path).ok() != Some(identity)
        {
            return Err(SecurityStateError::AnchorMismatch);
        }
        drop(read_only);
        let mut store = Self::open_admitted(path, Some(identity))?;
        store.security = Some(SecurityContext {
            profile,
            database: anchor.database_identity,
            path: path.to_path_buf(),
            file_identity: gocode_sqlite_native_identity::opened_database_identity(
                &store.connection,
            )
            .map_err(|_| SecurityStateError::AdmissionFailed)?,
            poisoned: false,
        });
        let migrated = store.migrate_v7_to_v8(secure, lock, anchor)?;
        secure.compare_and_advance_anchor(lock, anchor, &migrated)?;
        if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(migrated) {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        Ok(store)
    }

    pub(crate) fn migrate_v6(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
        lock: &gocode_secure_store::SecurityProfileLock<'_>,
        anchor: &SecurityAnchorV1,
    ) -> Result<Self, SecurityStateError> {
        let read_only =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let identity = gocode_sqlite_native_identity::opened_database_identity(&read_only)
            .map_err(|_| SecurityStateError::AdmissionFailed)?;
        crate::security_schema_v6::validate_v6_schema(&read_only)?;
        let bound: (Vec<u8>, Vec<u8>) = read_only.query_row("SELECT profile_identity_digest,database_identity FROM security_profile WHERE singleton=1", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
        if anchor.profile_identity_digest != profile
            || bound != (profile.to_vec(), anchor.database_identity.to_vec())
        {
            return Err(SecurityStateError::AnchorMismatch);
        }
        let persisted = crate::security_recovery::verify_persisted_anchor_chain(
            &read_only,
            secure,
            lock,
            profile,
            anchor.database_identity,
        )?;
        let generation: i64 = read_only.query_row(
            "SELECT db_generation FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if persisted != *anchor
            || u64::try_from(generation).ok() != Some(anchor.generation)
            || gocode_sqlite_native_identity::path_database_identity(path).ok() != Some(identity)
        {
            return Err(SecurityStateError::AnchorMismatch);
        }
        drop(read_only);
        let mut store = Self::open_admitted(path, Some(identity))?;
        store.security = Some(SecurityContext {
            profile,
            database: anchor.database_identity,
            path: path.to_path_buf(),
            file_identity: gocode_sqlite_native_identity::opened_database_identity(
                &store.connection,
            )
            .map_err(|_| SecurityStateError::AdmissionFailed)?,
            poisoned: false,
        });
        let migrated =
            store.migrate_v6_ledger(secure, lock, profile, anchor.database_identity, anchor)?;
        secure.compare_and_advance_anchor(lock, anchor, &migrated)?;
        if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(migrated.clone()) {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        drop(store);
        Self::migrate_v7(path, secure, profile, lock, &migrated)
    }
}
