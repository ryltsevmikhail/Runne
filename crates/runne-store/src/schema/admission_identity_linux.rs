impl ConnectionIdentityGuard {
    fn from_created(path: &Path, file: fs::File) -> Result<Self, SchemaOpenDiagnostic> {
        // Close the create descriptor before SQLite opens this inode: Linux
        // releases process-wide POSIX locks when any ordinary fd is closed.
        let created_identity = descriptor_identity(&file)?;
        let database = RetainedFileIdentity::open(path)?;
        if database.identity != created_identity {
            return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
        }
        drop(file);
        Ok(Self {
            database,
            wal: None,
            shm: None,
            owner_private: false,
        })
    }
}
