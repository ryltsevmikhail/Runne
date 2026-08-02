const PROVIDER_CREDENTIAL_MAGIC: &[u8; 8] = b"GCPCV1\0\0";
const PROVIDER_CREDENTIAL_METADATA_MAGIC: &[u8; 8] = b"GCPMDV1\0";
const PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_MAGIC: &[u8; 8] = b"GCPMDI1\0";
const EXECUTABLE_IDENTITY_BYTES: usize = 72;
const PROVIDER_CREDENTIAL_HEADER_BYTES: usize =
    PROVIDER_CREDENTIAL_MAGIC.len() + (2 * EXECUTABLE_IDENTITY_BYTES) + 32 + 4;
const PROVIDER_CREDENTIAL_METADATA_BYTES: usize =
    PROVIDER_CREDENTIAL_METADATA_MAGIC.len() + (2 * EXECUTABLE_IDENTITY_BYTES) + 32;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProviderCredentialEnrollmentState {
    Incomplete,
    Complete,
}

/// Fixed native secure-store service for provider credentials.
pub const PROVIDER_CREDENTIAL_SERVICE: &str = "dev.gocode.provider-credential.v1";

/// Maximum accepted provider credential size in bytes.
pub const MAX_PROVIDER_CREDENTIAL_BYTES: usize = 4_096;

/// Closed provider credential identities supported by the first native profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialId {
    /// `OpenAI` Responses API credential.
    OpenAi,
}

impl ProviderCredentialId {
    /// Returns the fixed, non-secret native-store account.
    #[must_use]
    pub const fn account(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
        }
    }
}

/// Renderer- and CLI-safe credential availability vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialStatus {
    /// An exact native credential item is configured.
    Configured,
    /// No exact native credential item exists.
    Missing,
    /// This platform has no accepted native backend.
    Unsupported,
}

impl fmt::Display for ProviderCredentialStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configured => "configured",
            Self::Missing => "missing",
            Self::Unsupported => "unsupported",
        })
    }
}

/// Zeroizing, bounded provider credential material.
pub struct ProviderCredentialMaterial {
    bytes: Zeroizing<Vec<u8>>,
}

impl ProviderCredentialMaterial {
    /// Validates and takes ownership of one non-empty, single-line secret.
    ///
    /// # Errors
    ///
    /// Returns [`SecureStoreError::InvalidProviderCredential`] for an empty,
    /// oversized, NUL-containing or multi-line value.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecureStoreError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty()
            || bytes.len() > MAX_PROVIDER_CREDENTIAL_BYTES
            || bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err(SecureStoreError::InvalidProviderCredential);
        }
        Ok(Self { bytes })
    }

    /// Borrows credential bytes only for the duration of `operation`.
    pub fn with_bytes<T>(&self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(&self.bytes)
    }
}

impl fmt::Debug for ProviderCredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredentialMaterial")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Exact canonical writer and reader executable identities for one item ACL.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderCredentialAccessPolicy {
    writer_path: PathBuf,
    writer_identity: ExecutableIdentityV1,
    reader_path: PathBuf,
    reader_identity: ExecutableIdentityV1,
}

impl ProviderCredentialAccessPolicy {
    /// Measures canonical executable identities for a development/ad-hoc ACL.
    ///
    /// Path measurement and legacy Keychain trusted-application construction
    /// are separate OS operations. Callers must therefore exclude untrusted
    /// same-UID processes during development enrollment. Production enrollment
    /// remains blocked until writer and daemon identities are supplied by an
    /// authenticated live-process handshake rather than mutable paths.
    ///
    /// # Errors
    ///
    /// Returns a closed identity failure for a missing, non-executable,
    /// writable or otherwise unmeasurable path.
    pub fn new(writer_path: &Path, reader_path: &Path) -> Result<Self, SecureStoreError> {
        let (writer_path, writer_identity) = measure_executable(writer_path)?;
        let (reader_path, reader_identity) = measure_executable(reader_path)?;
        Ok(Self { writer_path, writer_identity, reader_path, reader_identity })
    }

    #[must_use]
    pub const fn writer_identity(&self) -> &ExecutableIdentityV1 { &self.writer_identity }
    #[must_use]
    pub const fn reader_identity(&self) -> &ExecutableIdentityV1 { &self.reader_identity }
    pub(crate) fn writer_path(&self) -> &Path { &self.writer_path }
    pub(crate) fn reader_path(&self) -> &Path { &self.reader_path }
    pub(crate) fn validate_writer_current(&self) -> Result<(), SecureStoreError> { validate_current_identity(&self.writer_identity) }
    pub(crate) fn validate_reader_current(&self) -> Result<(), SecureStoreError> { validate_current_identity(&self.reader_identity) }
    pub(crate) fn validate_writer_or_reader_current(&self) -> Result<(), SecureStoreError> {
        if self.validate_writer_current().is_ok() || self.validate_reader_current().is_ok() { Ok(()) } else { Err(SecureStoreError::CredentialAccessDenied) }
    }
    pub(crate) fn remeasure(&self) -> Result<(), SecureStoreError> {
        let (_, writer) = measure_executable(&self.writer_path)?;
        let (_, reader) = measure_executable(&self.reader_path)?;
        if writer != self.writer_identity || reader != self.reader_identity { return Err(SecureStoreError::CredentialIdentityMismatch); }
        Ok(())
    }
}

impl fmt::Debug for ProviderCredentialAccessPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ProviderCredentialAccessPolicy").field("writer", &"<measured>").field("reader", &"<measured>").finish()
    }
}

fn validate_current_identity(expected: &ExecutableIdentityV1) -> Result<(), SecureStoreError> {
    let current = std::env::current_exe().map_err(|_| SecureStoreError::CredentialIdentityMismatch)?;
    let (_, measured) = measure_executable(&current)?;
    if &measured != expected { return Err(SecureStoreError::CredentialIdentityMismatch); }
    Ok(())
}

fn measure_executable(path: &Path) -> Result<(PathBuf, ExecutableIdentityV1), SecureStoreError> {
    let canonical = std::fs::canonicalize(path).map_err(|_| SecureStoreError::CredentialIdentityMismatch)?;
    if !canonical.is_absolute() { return Err(SecureStoreError::CredentialIdentityMismatch); }
    let metadata = std::fs::symlink_metadata(&canonical).map_err(|_| SecureStoreError::CredentialIdentityMismatch)?;
    if !metadata.is_file() || metadata.len() == 0 { return Err(SecureStoreError::CredentialIdentityMismatch); }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 { return Err(SecureStoreError::CredentialIdentityMismatch); }
    }
    let identity = ExecutableIdentityV1::measure(&canonical).map_err(|_| SecureStoreError::CredentialIdentityMismatch)?;
    Ok((canonical, identity))
}
