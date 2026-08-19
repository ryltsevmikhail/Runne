use crate::{Connection, LocalStore, Path, SecurityStateError};
use runne_secure_store::{SecureStore, StoredSecurityAnchor};
use runne_sqlite_native_identity::{opened_database_identity, path_database_identity};

impl LocalStore {
    pub(crate) fn resume_legacy_v7(
        path: &Path,
        secure: &dyn SecureStore,
        profile: [u8; 32],
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        generation: u64,
    ) -> Result<Self, SecurityStateError> {
        let read_only =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let file_identity = opened_database_identity(&read_only)
            .map_err(|_| SecurityStateError::AdmissionFailed)?;
        crate::security_schema_v7::validate_v7_schema(&read_only)?;
        let database = crate::security_open_hash::database_identity(path)?;
        let bound: (Vec<u8>, Vec<u8>) = read_only.query_row(
            "SELECT profile_identity_digest,database_identity FROM security_profile WHERE singleton=1", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let persisted = crate::security_recovery::verify_persisted_anchor_chain(
            &read_only, secure, lock, profile, database,
        )?;
        let db_generation: i64 = read_only.query_row(
            "SELECT db_generation FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let expected = generation
            .checked_add(1)
            .ok_or(SecurityStateError::AnchorMismatch)?;
        if bound != (profile.to_vec(), database.to_vec())
            || u64::try_from(db_generation).ok() != Some(expected)
            || persisted.generation != expected
            || persisted.previous_anchor_digest
                != crate::security_open_hash::digest(
                    b"runne/security/legacy-anchor/v1\0",
                    &generation.to_be_bytes(),
                )
            || path_database_identity(path).ok() != Some(file_identity)
        {
            return Err(SecurityStateError::AnchorMismatch);
        }
        drop(read_only);
        secure.compare_and_migrate_legacy_anchor(lock, generation, &persisted)?;
        if secure.read_security_anchor(lock)? != StoredSecurityAnchor::V1(persisted.clone()) {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        Self::migrate_v7(path, secure, profile, lock, &persisted)
    }
}
