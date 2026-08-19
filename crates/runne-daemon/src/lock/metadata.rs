// ── Metadata I/O ──────────────────────────────────────────────────────

/// Read the 25-byte metadata record from a lock file.
///
/// Reads from the beginning of the file. Returns `Empty` for zero-length
/// files, `Malformed` for non-zero-length files that don't contain exactly
/// 25 bytes or have an invalid record.
fn read_lock_metadata(file: &std::fs::File) -> Result<MetadataSnapshot, DaemonError> {
    let meta = file
        .metadata()
        .map_err(|e| DaemonError::Lock(format!("failed to read lock file metadata: {e}")))?;

    let len = meta.len();
    if len == 0 {
        return Ok(MetadataSnapshot::Empty);
    }

    if len != LockMetadata::RECORD_SIZE as u64 {
        return Ok(MetadataSnapshot::Malformed);
    }

    // Seek to beginning and read exactly 25 bytes.
    // &File implements Seek since Rust 1.51.
    (&*file)
        .seek(SeekFrom::Start(0))
        .map_err(|e| DaemonError::Lock(format!("failed to seek lock file: {e}")))?;

    let mut buf = [0u8; LockMetadata::RECORD_SIZE];
    (&*file)
        .read_exact(&mut buf)
        .map_err(|e| DaemonError::Lock(format!("failed to read lock metadata: {e}")))?;

    match LockMetadata::from_bytes(&buf) {
        Some(meta) => Ok(MetadataSnapshot::Valid {
            authority_id: meta.authority_id,
        }),
        None => Ok(MetadataSnapshot::Malformed),
    }
}

/// Write metadata to a lock file.
///
/// Truncates the file, writes the 25-byte record, and syncs to disk.
fn write_lock_metadata(file: &std::fs::File, metadata: &LockMetadata) -> Result<(), DaemonError> {
    file.set_len(0)
        .map_err(|e| DaemonError::Lock(format!("failed to truncate lock file: {e}")))?;

    (&*file)
        .seek(SeekFrom::Start(0))
        .map_err(|e| DaemonError::Lock(format!("failed to seek lock file: {e}")))?;

    let bytes = metadata.to_bytes();
    (&*file)
        .write_all(&bytes)
        .map_err(|e| DaemonError::Lock(format!("failed to write lock metadata: {e}")))?;

    (&*file)
        .flush()
        .map_err(|e| DaemonError::Lock(format!("failed to flush lock metadata: {e}")))?;

    file.sync_all()
        .map_err(|e| DaemonError::Lock(format!("failed to sync lock file: {e}")))?;

    Ok(())
}
