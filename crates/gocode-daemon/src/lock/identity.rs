// ── Platform-independent helpers ──────────────────────────────────────

/// Canonicalise a path, resolving all symlinks.
fn canonicalize_path(path: &Path) -> Result<PathBuf, DaemonError> {
    fs::canonicalize(path)
        .or_else(|_| -> std::io::Result<PathBuf> {
            let parent = path.parent().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
            })?;
            let name = path.file_name().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
            })?;
            Ok(fs::canonicalize(parent)?.join(name))
        })
        .map_err(|e| {
            DaemonError::Lock(format!(
                "failed to canonicalise path {path}: {e}",
                path = path.display()
            ))
        })
}

/// Get a platform-level file identity string.
///
/// Unix: `"{dev}:{ino}"` (device + inode).
/// Windows: `"{vol_serial}:{file_id}"` (volume serial + file ID).
fn platform_file_identity(file: &std::fs::File) -> Result<String, DaemonError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file
            .metadata()
            .map_err(|e| DaemonError::Lock(format!("failed to read file metadata: {e}")))?;
        let dev = meta.dev();
        let ino = meta.ino();
        Ok(format!("{dev}:{ino}"))
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };

        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
        if succeeded == 0 {
            return Err(DaemonError::Lock(format!(
                "failed to read Windows file identity: {}",
                std::io::Error::last_os_error()
            )));
        }
        let info = unsafe { info.assume_init() };
        let vol_serial = info.dwVolumeSerialNumber;
        let file_index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        Ok(format!("{vol_serial}:{file_index}"))
    }
}

/// CRC32 checksum (IEEE 802.3 / gzip / CRC32fast).
fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}
