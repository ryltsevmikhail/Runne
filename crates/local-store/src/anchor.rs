/// Verifies the relationship between the `SQLite` `db_generation` and the
/// OS secure-store anchor. Returns the classified state per
/// `CLIENT_STORAGE_AND_RECOVERY.md` recovery state machine.
///
/// # Errors
///
/// Returns an error if the database cannot be read or the secure store
/// is unavailable.
pub fn verify_anchor(
    store: &LocalStore,
    secure_store: &dyn SecureStore,
) -> Result<AnchorStatus, AnchorError> {
    let (db_gen, valid_commit_marker) = store.get_anchor_evidence()?;
    let anchor = secure_store.read_anchor()?;

    Ok(match anchor {
        None => AnchorStatus::AnchorMissing { db_gen },
        Some(a) if db_gen == a => AnchorStatus::Normal,
        Some(a) if db_gen < a => AnchorStatus::DbLowerThanAnchor { db_gen, anchor: a },
        Some(a) if a.checked_add(1) == Some(db_gen) && valid_commit_marker => {
            AnchorStatus::DbOneAhead { db_gen, anchor: a }
        }
        Some(a) => AnchorStatus::DbTooFarAhead { db_gen, anchor: a },
    })
}

/// Stores the current `db_generation` as an OS secure-store anchor.
///
/// # Errors
///
/// Returns an error if the database cannot be read or the secure store
/// write fails.
pub fn anchor_db_generation(
    store: &LocalStore,
    secure_store: &dyn SecureStore,
) -> Result<(), AnchorError> {
    secure_store.store_anchor(store.get_db_generation()?)?;
    Ok(())
}

impl LocalStore {
    /// Returns the current `db_generation` from the meta table.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be read or the stored generation
    /// cannot be represented as an unsigned integer.
    pub fn get_db_generation(&self) -> Result<u64, AnchorError> {
        let generation: i64 = self.connection.query_row(
            "SELECT db_generation FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(generation).map_err(|_| AnchorError::GenerationOutOfRange)
    }

    fn get_anchor_evidence(&self) -> Result<(u64, bool), AnchorError> {
        let (generation, commit_marker): (i64, i64) = self.connection.query_row(
            "SELECT db_generation, commit_marker FROM meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let generation =
            u64::try_from(generation).map_err(|_| AnchorError::GenerationOutOfRange)?;
        Ok((generation, commit_marker == 1))
    }
}
