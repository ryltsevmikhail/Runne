// Linux test-only factory provenance; not direct SQLite-handle attestation.
// This descriptor outlives its originating connection without ordinary-fd close.
pub(crate) struct TestOriginalDatabaseAnchor {
    main: RetainedFileIdentity,
}

impl ManagedConnection {
    pub(crate) fn retain_test_original_anchor(&self) -> SqliteResult<TestOriginalDatabaseAnchor> {
        self.verify_retained_identity()?;
        if self._validated.memory_database {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let guard = self.identity.as_ref().ok_or(rusqlite::Error::InvalidQuery)?;
        // Linux factory main anchors are O_PATH, including from_created.
        // try_clone duplicates that existing open description, not a path reopen.
        let duplicate = guard.database.file.try_clone()
            .map_err(|_| diagnostic_error(SchemaOpenDiagnostic::FileIdentityUncertain))?;
        let main = RetainedFileIdentity::from_file(&guard.database.path, duplicate)
            .map_err(diagnostic_error)?;
        self.verify_retained_identity()?;
        if main.identity != guard.database.identity || !main.unchanged().map_err(diagnostic_error)? {
            return Err(diagnostic_error(SchemaOpenDiagnostic::FileIdentityUncertain));
        }
        Ok(TestOriginalDatabaseAnchor { main })
    }
}

impl TestOriginalDatabaseAnchor {
    pub(crate) fn verify(&self) -> SqliteResult<()> {
        if !self.main.unchanged().map_err(diagnostic_error)? {
            return Err(diagnostic_error(SchemaOpenDiagnostic::FileIdentityUncertain));
        }
        Ok(())
    }

    pub(crate) fn verify_reader(&self, reader: &ManagedConnection) -> SqliteResult<()> {
        self.verify()?;
        reader.verify_retained_identity()?;
        if reader._validated.mode != ConnectionMode::Reader || reader._validated.memory_database {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let guard = reader.identity.as_ref().ok_or(rusqlite::Error::InvalidQuery)?;
        if guard.database.identity != self.main.identity {
            return Err(diagnostic_error(SchemaOpenDiagnostic::FileIdentityUncertain));
        }
        self.verify()?;
        reader.verify_retained_identity()
    }
}

#[cfg(test)]
#[path = "test_original_anchor_tests.rs"]
mod test_original_anchor_tests;
