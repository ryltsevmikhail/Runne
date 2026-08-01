impl LockSet {
    // ── Step 1: acquire path lock ─────────────────────────────────

    /// Acquire the provisional path lock.
    ///
    /// `db_path` is the raw path from configuration (may contain symlinks).
    /// `runtime_dir` is where `gocode-daemon/` lock files are stored.
    ///
    /// This must be the first lock acquired — before the DB is opened.
    pub fn acquire_path(db_path: &Path, runtime_dir: &Path) -> Result<Self, DaemonError> {
        let canonical = canonicalize_path(db_path)?;
        let path_hash = sha256_hex(canonical.to_str().unwrap_or("").as_bytes());
        let lock_dir = runtime_dir.join("gocode-daemon");
        let lock_path = lock_dir.join(format!("path-{path_hash}.lock"));

        fs::create_dir_all(&lock_dir)
            .map_err(|e| DaemonError::Lock(format!("failed to create lock directory: {e}")))?;

        let file = open_or_create_lockfile(&lock_path)?;

        file.try_lock_exclusive().map_err(|e| {
            DaemonError::Lock(format!(
                "failed to acquire exclusive lock on {path}: {e}",
                path = lock_path.display()
            ))
        })?;

        Ok(Self {
            path_lock: LockGuard::new(file),
            file_lock: None,
            authority_lock: None,
        })
    }

    // ── Metadata I/O on the path lock ────────────────────────────

    /// Read the metadata snapshot from the path-lock file.
    ///
    /// Reads exactly 25 bytes (or detects empty/malformed state).
    /// Called **before** opening the DB to determine startup scenario.
    pub fn read_metadata_snapshot(&self) -> Result<MetadataSnapshot, DaemonError> {
        read_lock_metadata(self.path_lock.file())
    }

    /// Write authority metadata into the path-lock file.
    ///
    /// Uses `set_len(0)` + `write_all` + `sync_all` for atomic-like update.
    pub fn write_metadata(&self, authority_id: &[u8; 16]) -> Result<(), DaemonError> {
        let metadata = LockMetadata {
            authority_id: *authority_id,
        };
        write_lock_metadata(self.path_lock.file(), &metadata)
    }

    // ── Step 2: acquire file identity lock ───────────────────────

    /// Acquire the file identity lock.
    ///
    /// Must be called **after** obtaining a no-follow verify handle to the DB.
    /// Uses the platform-level file identity (inode/volume on Unix;
    /// volume serial + file ID on Windows) to detect hardlink/rename aliases.
    pub fn acquire_file_lock(
        &mut self,
        db_handle: &std::fs::File,
        runtime_dir: &Path,
    ) -> Result<(), DaemonError> {
        let identity = platform_file_identity(db_handle)?;
        let file_hash = sha256_hex(identity.as_bytes());
        let lock_dir = runtime_dir.join("gocode-daemon");
        let lock_path = lock_dir.join(format!("file-{file_hash}.lock"));

        let file = open_or_create_lockfile(&lock_path)?;
        file.try_lock_exclusive()
            .map_err(|e| DaemonError::Lock(format!("failed to acquire file identity lock: {e}")))?;

        self.file_lock = Some(LockGuard::new(file));
        Ok(())
    }

    // ── Step 3: acquire authority lock ───────────────────────────

    /// Acquire the authority lock.
    ///
    /// Must be called **after** reading `_authority` from a schema v7 DB (or
    /// generating it for a new DB). Uses the authority_id to guard separate
    /// copies of the same Event Log.
    pub fn acquire_authority_lock(
        &mut self,
        authority_id: &[u8; 16],
        runtime_dir: &Path,
    ) -> Result<(), DaemonError> {
        let auth_hash = sha256_hex(authority_id);
        let lock_dir = runtime_dir.join("gocode-daemon");
        let lock_path = lock_dir.join(format!("authority-{auth_hash}.lock"));

        let file = open_or_create_lockfile(&lock_path)?;
        file.try_lock_exclusive()
            .map_err(|e| DaemonError::Lock(format!("failed to acquire authority lock: {e}")))?;

        self.authority_lock = Some(LockGuard::new(file));
        Ok(())
    }
}
