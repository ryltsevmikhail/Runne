use core::fmt;
use std::path::{Path, PathBuf};

use gocode_api::ExecutableIdentityV1;
use zeroize::Zeroizing;

use crate::SecureStoreError;

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
        Ok(Self {
            writer_path,
            writer_identity,
            reader_path,
            reader_identity,
        })
    }

    /// Returns the exact non-secret writer identity.
    #[must_use]
    pub const fn writer_identity(&self) -> &ExecutableIdentityV1 {
        &self.writer_identity
    }

    /// Returns the exact non-secret reader identity.
    #[must_use]
    pub const fn reader_identity(&self) -> &ExecutableIdentityV1 {
        &self.reader_identity
    }

    pub(crate) fn writer_path(&self) -> &Path {
        &self.writer_path
    }

    pub(crate) fn reader_path(&self) -> &Path {
        &self.reader_path
    }

    pub(crate) fn validate_writer_current(&self) -> Result<(), SecureStoreError> {
        validate_current_identity(&self.writer_identity)
    }

    pub(crate) fn validate_reader_current(&self) -> Result<(), SecureStoreError> {
        validate_current_identity(&self.reader_identity)
    }

    pub(crate) fn validate_writer_or_reader_current(&self) -> Result<(), SecureStoreError> {
        if self.validate_writer_current().is_ok() || self.validate_reader_current().is_ok() {
            Ok(())
        } else {
            Err(SecureStoreError::CredentialAccessDenied)
        }
    }

    pub(crate) fn remeasure(&self) -> Result<(), SecureStoreError> {
        let (_, writer) = measure_executable(&self.writer_path)?;
        let (_, reader) = measure_executable(&self.reader_path)?;
        if writer != self.writer_identity || reader != self.reader_identity {
            return Err(SecureStoreError::CredentialIdentityMismatch);
        }
        Ok(())
    }
}

pub struct StoredProviderCredential {
    writer_identity: ExecutableIdentityV1,
    reader_identity: ExecutableIdentityV1,
    acl_set_digest: [u8; 32],
    material: ProviderCredentialMaterial,
}

/// Non-secret item metadata used for pre-readiness presence and ACL checks.
pub struct ProviderCredentialMetadata {
    enrollment_state: ProviderCredentialEnrollmentState,
    writer_identity: ExecutableIdentityV1,
    reader_identity: ExecutableIdentityV1,
    acl_set_digest: [u8; 32],
}

impl ProviderCredentialMetadata {
    pub fn from_access(access: &ProviderCredentialAccessPolicy, acl_set_digest: [u8; 32]) -> Self {
        Self {
            enrollment_state: ProviderCredentialEnrollmentState::Complete,
            writer_identity: access.writer_identity().clone(),
            reader_identity: access.reader_identity().clone(),
            acl_set_digest,
        }
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SecureStoreError> {
        if encoded.len() != PROVIDER_CREDENTIAL_METADATA_BYTES {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        let magic = &encoded[..PROVIDER_CREDENTIAL_METADATA_MAGIC.len()];
        let enrollment_state = if magic == PROVIDER_CREDENTIAL_METADATA_MAGIC {
            ProviderCredentialEnrollmentState::Complete
        } else if magic == PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_MAGIC {
            ProviderCredentialEnrollmentState::Incomplete
        } else {
            return Err(SecureStoreError::CorruptProviderCredential);
        };
        let mut offset = PROVIDER_CREDENTIAL_METADATA_MAGIC.len();
        let writer_identity = decode_identity(encoded, &mut offset)?;
        let reader_identity = decode_identity(encoded, &mut offset)?;
        let acl_set_digest = take(encoded, &mut offset)?;
        if acl_set_digest == [0; 32] {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        Ok(Self {
            enrollment_state,
            writer_identity,
            reader_identity,
            acl_set_digest,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_with_state(ProviderCredentialEnrollmentState::Complete)
    }

    pub fn encode_incomplete(&self) -> Vec<u8> {
        self.encode_with_state(ProviderCredentialEnrollmentState::Incomplete)
    }

    fn encode_with_state(&self, state: ProviderCredentialEnrollmentState) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(PROVIDER_CREDENTIAL_METADATA_BYTES);
        encoded.extend_from_slice(match state {
            ProviderCredentialEnrollmentState::Incomplete => {
                PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_MAGIC
            }
            ProviderCredentialEnrollmentState::Complete => PROVIDER_CREDENTIAL_METADATA_MAGIC,
        });
        encode_identity(&mut encoded, &self.writer_identity);
        encode_identity(&mut encoded, &self.reader_identity);
        encoded.extend_from_slice(&self.acl_set_digest);
        encoded
    }

    pub fn is_complete(&self) -> bool {
        self.enrollment_state == ProviderCredentialEnrollmentState::Complete
    }

    pub fn validate_writer_current(&self) -> Result<(), SecureStoreError> {
        validate_current_identity(&self.writer_identity)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }

    pub const fn acl_set_digest(&self) -> [u8; 32] {
        self.acl_set_digest
    }

    pub fn access_matches(&self, access: &ProviderCredentialAccessPolicy) -> bool {
        self.writer_identity == *access.writer_identity()
            && self.reader_identity == *access.reader_identity()
    }
}

impl StoredProviderCredential {
    pub fn decode(encoded: &[u8]) -> Result<Self, SecureStoreError> {
        if encoded.len() < PROVIDER_CREDENTIAL_HEADER_BYTES
            || &encoded[..PROVIDER_CREDENTIAL_MAGIC.len()] != PROVIDER_CREDENTIAL_MAGIC
        {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        let mut offset = PROVIDER_CREDENTIAL_MAGIC.len();
        let writer_identity = decode_identity(encoded, &mut offset)?;
        let reader_identity = decode_identity(encoded, &mut offset)?;
        let acl_set_digest = take(encoded, &mut offset)?;
        if acl_set_digest == [0; 32] {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        let credential_length = usize::try_from(u32::from_be_bytes(take(encoded, &mut offset)?))
            .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
        let expected_length = offset
            .checked_add(credential_length)
            .ok_or(SecureStoreError::CorruptProviderCredential)?;
        if credential_length == 0
            || credential_length > MAX_PROVIDER_CREDENTIAL_BYTES
            || encoded.len() != expected_length
        {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        let material = ProviderCredentialMaterial::new(encoded[offset..].to_vec())
            .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
        Ok(Self {
            writer_identity,
            reader_identity,
            acl_set_digest,
            material,
        })
    }

    pub fn encode(
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
        acl_set_digest: [u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        if acl_set_digest == [0; 32] {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        let credential_length = material.with_bytes(<[u8]>::len);
        let encoded_length = PROVIDER_CREDENTIAL_HEADER_BYTES
            .checked_add(credential_length)
            .ok_or(SecureStoreError::InvalidProviderCredential)?;
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(encoded_length)
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
        encoded.extend_from_slice(PROVIDER_CREDENTIAL_MAGIC);
        encode_identity(&mut encoded, access.writer_identity());
        encode_identity(&mut encoded, access.reader_identity());
        encoded.extend_from_slice(&acl_set_digest);
        encoded.extend_from_slice(
            &u32::try_from(credential_length)
                .map_err(|_| SecureStoreError::InvalidProviderCredential)?
                .to_be_bytes(),
        );
        material.with_bytes(|bytes| encoded.extend_from_slice(bytes));
        Ok(encoded)
    }

    pub fn access_matches(&self, access: &ProviderCredentialAccessPolicy) -> bool {
        self.writer_identity == *access.writer_identity()
            && self.reader_identity == *access.reader_identity()
    }

    pub fn metadata_matches(&self, metadata: &ProviderCredentialMetadata) -> bool {
        self.writer_identity == metadata.writer_identity
            && self.reader_identity == metadata.reader_identity
            && self.acl_set_digest == metadata.acl_set_digest
    }

    #[cfg(test)]
    pub fn validate_reader_current(&self) -> Result<(), SecureStoreError> {
        validate_current_identity(&self.reader_identity)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }

    pub const fn acl_set_digest(&self) -> [u8; 32] {
        self.acl_set_digest
    }

    pub fn into_material(self) -> ProviderCredentialMaterial {
        self.material
    }
}

fn encode_identity(encoded: &mut Vec<u8>, identity: &ExecutableIdentityV1) {
    encoded.extend_from_slice(identity.executable_sha256());
    encoded.extend_from_slice(identity.canonical_path_sha256());
    encoded.extend_from_slice(&identity.byte_length().to_be_bytes());
}

fn decode_identity(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<ExecutableIdentityV1, SecureStoreError> {
    let executable_sha256 = take(encoded, offset)?;
    let canonical_path_sha256 = take(encoded, offset)?;
    let byte_length = u64::from_be_bytes(take(encoded, offset)?);
    ExecutableIdentityV1::new(executable_sha256, canonical_path_sha256, byte_length)
        .map_err(|_| SecureStoreError::CorruptProviderCredential)
}

fn take<const N: usize>(encoded: &[u8], offset: &mut usize) -> Result<[u8; N], SecureStoreError> {
    let end = offset
        .checked_add(N)
        .ok_or(SecureStoreError::CorruptProviderCredential)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(SecureStoreError::CorruptProviderCredential)?
        .try_into()
        .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
    *offset = end;
    Ok(value)
}

impl fmt::Debug for ProviderCredentialAccessPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredentialAccessPolicy")
            .field("writer", &"<measured>")
            .field("reader", &"<measured>")
            .finish()
    }
}

fn validate_current_identity(expected: &ExecutableIdentityV1) -> Result<(), SecureStoreError> {
    let current =
        std::env::current_exe().map_err(|_| SecureStoreError::CredentialIdentityMismatch)?;
    let (_, measured) = measure_executable(&current)?;
    if &measured != expected {
        return Err(SecureStoreError::CredentialIdentityMismatch);
    }
    Ok(())
}

fn measure_executable(path: &Path) -> Result<(PathBuf, ExecutableIdentityV1), SecureStoreError> {
    let canonical =
        std::fs::canonicalize(path).map_err(|_| SecureStoreError::CredentialIdentityMismatch)?;
    if !canonical.is_absolute() {
        return Err(SecureStoreError::CredentialIdentityMismatch);
    }
    let metadata = std::fs::symlink_metadata(&canonical)
        .map_err(|_| SecureStoreError::CredentialIdentityMismatch)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(SecureStoreError::CredentialIdentityMismatch);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            return Err(SecureStoreError::CredentialIdentityMismatch);
        }
    }
    let identity = ExecutableIdentityV1::measure(&canonical)
        .map_err(|_| SecureStoreError::CredentialIdentityMismatch)?;
    Ok((canonical, identity))
}

/// Native provider credential lifecycle boundary.
pub trait ProviderCredentialStore: Send + Sync {
    /// Returns only a closed, non-secret availability state under a freshly
    /// measured caller-supplied expected writer/reader binding.
    ///
    /// # Errors
    ///
    /// Returns a typed secure-store failure when status cannot be determined.
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError>;

    /// Persists one credential under an exact writer/reader ACL.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, identity, access or backend failure.
    fn store_provider_credential(
        &self,
        provider: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;

    /// Materializes one credential only for its exact enrolled reader under a
    /// freshly measured caller-supplied expected writer/reader binding.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, identity, access, corruption or backend failure.
    fn load_provider_credential(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;

    /// Idempotently deletes only the exact provider item as its writer.
    ///
    /// # Errors
    ///
    /// Returns a typed identity, access, corruption or backend failure.
    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError>;

    /// Explicitly replaces a previously enrolled executable ACL.
    ///
    /// # Errors
    ///
    /// Returns a typed identity, access, migration or backend failure.
    fn migrate_provider_credential_access(
        &self,
        provider: ProviderCredentialId,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ExecutableCopy(PathBuf);

    impl Drop for ExecutableCopy {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn enrolled_reader_mismatch_is_a_closed_access_denial() {
        let current = std::env::current_exe().expect("current test executable");
        let reader = ExecutableCopy(unique_executable_copy(&current, "reader-mismatch"));
        let policy = ProviderCredentialAccessPolicy::new(&current, &reader.0).unwrap();
        let material = ProviderCredentialMaterial::new(b"test-only-marker".to_vec()).unwrap();
        let encoded = StoredProviderCredential::encode(&material, &policy, [7; 32]).unwrap();
        let stored = StoredProviderCredential::decode(&encoded).unwrap();

        assert_eq!(
            stored.validate_reader_current(),
            Err(SecureStoreError::CredentialAccessDenied)
        );
    }

    fn unique_executable_copy(source: &Path, label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gocode-secure-store-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::copy(source, &path).expect("copy executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
                .expect("restrict copied executable");
        }
        path
    }

    #[test]
    fn complete_metadata_preserves_v1_upgrade_and_rollback_layout() {
        let current = std::env::current_exe().unwrap();
        let access = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let metadata = ProviderCredentialMetadata::from_access(&access, [7; 32]);

        let encoded = metadata.encode();

        assert_eq!(encoded.len(), 184);
        assert_eq!(&encoded[..8], b"GCPMDV1\0");
        assert!(
            ProviderCredentialMetadata::decode(&encoded)
                .unwrap()
                .is_complete()
        );
        assert_ne!(&metadata.encode_incomplete()[..8], b"GCPMDV1\0");
    }
}
