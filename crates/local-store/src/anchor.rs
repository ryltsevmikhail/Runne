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
}
