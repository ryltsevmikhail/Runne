/// Exact digest identity of the executable which is about to run.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutableIdentityV1 {
    executable_sha256: [u8; 32],
    canonical_path_sha256: [u8; 32],
    byte_length: u64,
}

impl ExecutableIdentityV1 {
    /// Creates a non-empty executable identity.
    pub fn new(
        executable_sha256: [u8; 32],
        canonical_path_sha256: [u8; 32],
        byte_length: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if executable_sha256 == [0; 32] || canonical_path_sha256 == [0; 32] || byte_length == 0 {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        Ok(Self {
            executable_sha256,
            canonical_path_sha256,
            byte_length,
        })
    }

    /// Measures an absolute regular executable through an opened file handle.
    pub fn measure(path: &std::path::Path) -> Result<Self, LaunchAuthorityError> {
        use std::io::Read as _;

        let canonical = std::fs::canonicalize(path)
            .map_err(|_| LaunchAuthorityError::ExecutableIdentityMismatch)?;
        if !canonical.is_absolute() {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        let mut file = std::fs::File::open(&canonical)
            .map_err(|_| LaunchAuthorityError::ExecutableIdentityMismatch)?;
        let metadata = file
            .metadata()
            .map_err(|_| LaunchAuthorityError::ExecutableIdentityMismatch)?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
            }
        }
        let mut executable_hasher = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| LaunchAuthorityError::ExecutableIdentityMismatch)?;
            if read == 0 {
                break;
            }
            executable_hasher.update(&buffer[..read]);
        }
        let executable_sha256 = executable_hasher.finalize().into();
        let canonical_path_sha256 = hash_canonical_path(&canonical);
        Self::new(executable_sha256, canonical_path_sha256, metadata.len())
    }

    pub const fn executable_sha256(&self) -> &[u8; 32] {
        &self.executable_sha256
    }

    pub const fn canonical_path_sha256(&self) -> &[u8; 32] {
        &self.canonical_path_sha256
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

#[cfg(unix)]
fn hash_canonical_path(path: &std::path::Path) -> [u8; 32] {
    use std::os::unix::ffi::OsStrExt as _;
    Sha256::digest(path.as_os_str().as_bytes()).into()
}

#[cfg(windows)]
fn hash_canonical_path(path: &std::path::Path) -> [u8; 32] {
    use std::os::windows::ffi::OsStrExt as _;
    let mut hasher = Sha256::new();
    for unit in path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    hasher.finalize().into()
}

#[cfg(not(any(unix, windows)))]
fn hash_canonical_path(path: &std::path::Path) -> [u8; 32] {
    Sha256::digest(path.to_string_lossy().as_bytes()).into()
}

impl fmt::Debug for ExecutableIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableIdentityV1")
            .field("byte_length", &self.byte_length)
            .finish_non_exhaustive()
    }
}

/// Expected protected transport/profile contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedRuntimeProfileV1 {
    transport_profile_id: String,
    runtime_profile_schema_version: u32,
    profile_id: String,
    profile_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl ProtectedRuntimeProfileV1 {
    /// Creates a bounded profile expectation.
    pub fn new(
        transport_profile_id: impl Into<String>,
        runtime_profile_schema_version: u32,
        profile_id: impl Into<String>,
        profile_hash: [u8; 32],
        capability_digest: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        let transport_profile_id = transport_profile_id.into();
        let profile_id = profile_id.into();
        if !valid_text(&transport_profile_id, MAX_PROFILE_ID_BYTES)
            || !valid_text(&profile_id, MAX_PROFILE_ID_BYTES)
            || runtime_profile_schema_version == 0
            || profile_hash == [0; 32]
            || capability_digest == [0; 32]
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            transport_profile_id,
            runtime_profile_schema_version,
            profile_id,
            profile_hash,
            capability_digest,
        })
    }

    pub fn transport_profile_id(&self) -> &str {
        &self.transport_profile_id
    }

    pub const fn runtime_profile_schema_version(&self) -> u32 {
        self.runtime_profile_schema_version
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub const fn profile_hash(&self) -> &[u8; 32] {
        &self.profile_hash
    }

    pub const fn capability_digest(&self) -> &[u8; 32] {
        &self.capability_digest
    }
}
