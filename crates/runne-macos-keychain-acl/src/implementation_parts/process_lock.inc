/// Kernel-held lock for all provider credential Keychain operations.
///
/// Reentrant within one process: the first successful `acquire` registers the
/// locked directory descriptor in the process-global
/// `PROVIDER_CREDENTIAL_LOCK_STATE` registry, and any
/// further `acquire` while it is registered only takes a depth token instead
/// of opening and `flock`-ing the inode again. Exclusive across processes: the
/// registered descriptor keeps `flock(LOCK_EX)` on the owner-only lock
/// directory inode until the last depth token drops and closes it.
pub struct ProviderCredentialProcessLock {
    /// Whether dropping this guard releases one registered depth token.
    depth_token: bool,
}

/// Process-global registry of the currently held kernel lock descriptor.
struct ProviderCredentialLockState {
    descriptor: Option<File>,
    depth: usize,
}

// `Mutex` is spelled out because `security_profile_seal.inc` already imports
// the name into this shared module scope and a second `use` would be E0252.
static PROVIDER_CREDENTIAL_LOCK_STATE: std::sync::Mutex<ProviderCredentialLockState> =
    std::sync::Mutex::new(ProviderCredentialLockState {
        descriptor: None,
        depth: 0_usize,
    });

impl ProviderCredentialProcessLock {
    /// Acquires the fixed per-user lock independently of ambient environment.
    ///
    /// The lock is the owner-only directory inode itself, so there is no lock
    /// file that normal participants can unlink and recreate. Nested calls in
    /// the same process return a depth token without re-running the directory
    /// validations or re-locking: they were validated and locked at depth
    /// 0 -> 1 and stay so while the descriptor is registered.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the Darwin user cache root or lock
    /// directory is not an owner-only, non-symlink directory, or when the
    /// process-global lock state is poisoned.
    pub fn acquire() -> Result<Self, KeychainAclError> {
        // Held across the whole first acquisition so concurrent same-process
        // threads queue on this registry instead of deadlocking on a second
        // `flock` of the already-locked descriptor.
        let mut state = PROVIDER_CREDENTIAL_LOCK_STATE
            .lock()
            .map_err(|_| KeychainAclError::OperationFailed)?;
        if state.descriptor.is_some() {
            state.depth += 1;
            return Ok(Self {
                depth_token: true,
            });
        }
        let cache_path = darwin_user_cache_directory()?;
        let cache = open_validated_directory(&cache_path)?;
        let lock_name = CStr::from_bytes_with_nul(PROVIDER_CREDENTIAL_LOCK_DIRECTORY)
            .map_err(|_| KeychainAclError::OperationFailed)?;
        // SAFETY: cache fd and NUL-terminated name are live. EEXIST is accepted
        // only after opening and validating the existing directory below.
        let mkdir_status = unsafe { libc::mkdirat(cache.as_raw_fd(), lock_name.as_ptr(), 0o700) };
        if mkdir_status != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
        {
            return Err(KeychainAclError::OperationFailed);
        }
        // SAFETY: the validated cache directory and NUL-terminated relative
        // name are live. O_NOFOLLOW rejects a symlink as the final component.
        let lock_fd = unsafe {
            libc::openat(
                cache.as_raw_fd(),
                lock_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if lock_fd < 0 {
            return Err(KeychainAclError::OperationFailed);
        }
        // SAFETY: openat returned a new owned descriptor.
        let directory = unsafe { File::from_raw_fd(lock_fd) };
        validate_owner_only_directory(&directory)?;
        validate_directory_entry(cache.as_raw_fd(), lock_name, &directory)?;
        // SAFETY: directory fd remains live in the registry until the last
        // depth token drops; LOCK_EX is released by the kernel when the
        // descriptor is closed or the process dies.
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(KeychainAclError::OperationFailed);
        }
        validate_owner_only_directory(&directory)?;
        validate_directory_entry(cache.as_raw_fd(), lock_name, &directory)?;
        state.descriptor = Some(directory);
        state.depth = 1;
        // The registry is consistent from here on, so other same-process
        // acquires can already take the depth-token path.
        drop(state);
        Ok(Self {
            depth_token: true,
        })
    }
}

impl Drop for ProviderCredentialProcessLock {
    fn drop(&mut self) {
        if !self.depth_token {
            return;
        }
        // A poisoned registry cannot be repaired here; the kernel flock still
        // ends when the process exits, so the token release is best-effort.
        let Ok(mut state) = PROVIDER_CREDENTIAL_LOCK_STATE.lock() else {
            return;
        };
        state.depth = state.depth.saturating_sub(1);
        if state.depth == 0 {
            // Moving the descriptor out drops it, which closes the fd and
            // releases the kernel `flock(LOCK_EX)` on the directory inode.
            state.descriptor = None;
        }
    }
}
