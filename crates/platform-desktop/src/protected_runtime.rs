//! Development/ad-hoc protected bundled-runtime launch and supervision.
//!
//! This module deliberately makes no production signing or notarization claim.
//! The Unix backend is usable for local macOS development/ad-hoc execution and
//! for Linux contract testing. Unsupported native backends fail closed.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError, LaunchSecret,
    PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, PendingFirstActivationV1, ProtectedActivationKeys,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedOwnedLaunchV1, ProtectedReadyV1, ProtectedRenewRequestV1, ProtectedRenewTicketV1,
    ProtectedRuntimeProfileV1, ProtectedShutdownAckV1, ProtectedShutdownV1, StableRuntimeBindingV1,
};
use gocode_runtime_client::{
    AuthenticatedRuntimeClient, GOLDEN_BUNDLE_HASH, ProtectedBundledRuntimeProfile,
    REQUIRED_RUNTIME_CAPABILITIES, RuntimeTransportKind,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT, BundledRuntimeBackoff, BundledRuntimeLifecycleState,
    BundledRuntimeProcessStatus, BundledRuntimeRestartDisposition, BundledRuntimeStopDisposition,
};

const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;
const MAX_STATE_BYTES: u64 = 64 * 1024;
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
const LOCAL_PRINCIPAL: &str = "local-owner";
const STATE_SCHEMA_VERSION: u32 = 1;
const ACTIVATION_STATE_DIRECTORY: &str = ".desktop-protected-activation";
const STAGED_EXECUTABLE_DIRECTORY: &str = "executables-v1";
const STABLE_RECORD_FILE: &str = "stable-binding-v1.json";
const PENDING_RECORD_FILE: &str = "pending-first-activation-v1.json";

/// Closed, renderer-safe failure vocabulary for protected bundled activation.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProtectedBundledRuntimeError {
    #[error("unsupported_platform_backend")]
    UnsupportedPlatformBackend,
    #[error("bundled_executable_unavailable")]
    ExecutableUnavailable,
    #[error("bundled_executable_identity_mismatch")]
    ExecutableIdentityMismatch,
    #[error("protected_runtime_root_unavailable")]
    RuntimeRootUnavailable,
    #[error("protected_activation_state_unavailable")]
    ActivationStateUnavailable,
    #[error("protected_channel_unavailable")]
    ProtectedChannelUnavailable,
    #[error("bundled_spawn_failed")]
    SpawnFailed,
    #[error("bundled_readiness_timeout")]
    ReadinessTimeout,
    #[error("bundled_runtime_not_owned")]
    OwnershipMismatch,
    #[error("bundled_runtime_invalid_state")]
    InvalidState,
    #[error("bundled_runtime_restart_exhausted")]
    RestartExhausted,
    #[error("bundled_runtime_shutdown_incomplete")]
    ShutdownIncomplete,
    #[error("{0}")]
    LaunchAuthority(#[from] LaunchAuthorityError),
}

/// Canonical executable and owner-private runtime root for one local profile.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedBundledRuntimeLaunchSpec {
    executable: PathBuf,
    runtime_root: PathBuf,
    trusted_source_identity: ExecutableIdentityV1,
}

impl fmt::Debug for ProtectedBundledRuntimeLaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBundledRuntimeLaunchSpec")
            .field("executable", &"<measured>")
            .field("runtime_root", &"<owner-private>")
            .finish()
    }
}

impl ProtectedBundledRuntimeLaunchSpec {
    /// Validates one direct, absolute executable and owner-private runtime root.
    ///
    /// # Errors
    ///
    /// Returns a closed platform, executable, or runtime-root failure.
    pub fn new(
        executable: &Path,
        runtime_root: &Path,
    ) -> Result<Self, ProtectedBundledRuntimeError> {
        #[cfg(not(unix))]
        {
            let _ = (executable, runtime_root);
            return Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend);
        }
        #[cfg(unix)]
        {
            let executable = validate_executable_path(executable)?;
            let trusted_source_identity = ExecutableIdentityV1::measure(&executable)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            let runtime_root = ensure_owner_private_directory(runtime_root)?;
            Ok(Self {
                executable,
                runtime_root,
                trusted_source_identity,
            })
        }
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    const fn trusted_source_identity(&self) -> &ExecutableIdentityV1 {
        &self.trusted_source_identity
    }
}

/// Resolves the colocated bundled daemon without consulting `PATH` or a shell.
///
/// Release-style layouts require `gocoded`. Debug builds also admit the
/// current workspace binary name `gocode-daemon` for local development.
///
/// # Errors
///
/// Returns a closed failure when no absolute, regular, non-writable executable
/// can be measured or the platform backend is unsupported.
pub fn discover_bundled_runtime(
    desktop_executable: &Path,
) -> Result<PathBuf, ProtectedBundledRuntimeError> {
    #[cfg(not(unix))]
    {
        let _ = desktop_executable;
        Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
    }
    #[cfg(unix)]
    {
        let desktop = std::fs::canonicalize(desktop_executable)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
        let directory = desktop
            .parent()
            .ok_or(ProtectedBundledRuntimeError::ExecutableUnavailable)?;
        let primary = directory.join("gocoded");
        if primary.exists() {
            return validate_executable_path(&primary);
        }
        #[cfg(debug_assertions)]
        {
            let development = directory.join("gocode-daemon");
            if development.exists() {
                return validate_executable_path(&development);
            }
        }
        Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredExecutableV1 {
    executable_sha256: [u8; 32],
    canonical_path_sha256: [u8; 32],
    byte_length: u64,
}

impl StoredExecutableV1 {
    const fn from_contract(value: &ExecutableIdentityV1) -> Self {
        Self {
            executable_sha256: *value.executable_sha256(),
            canonical_path_sha256: *value.canonical_path_sha256(),
            byte_length: value.byte_length(),
        }
    }

    fn into_contract(self) -> Result<ExecutableIdentityV1, ProtectedBundledRuntimeError> {
        ExecutableIdentityV1::new(
            self.executable_sha256,
            self.canonical_path_sha256,
            self.byte_length,
        )
        .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProfileV1 {
    transport_profile_id: String,
    runtime_profile_schema_version: u32,
    profile_id: String,
    profile_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl StoredProfileV1 {
    fn from_contract(value: &ProtectedRuntimeProfileV1) -> Self {
        Self {
            transport_profile_id: value.transport_profile_id().to_owned(),
            runtime_profile_schema_version: value.runtime_profile_schema_version(),
            profile_id: value.profile_id().to_owned(),
            profile_hash: *value.profile_hash(),
            capability_digest: *value.capability_digest(),
        }
    }

    fn into_contract(self) -> Result<ProtectedRuntimeProfileV1, ProtectedBundledRuntimeError> {
        ProtectedRuntimeProfileV1::new(
            self.transport_profile_id,
            self.runtime_profile_schema_version,
            self.profile_id,
            self.profile_hash,
            self.capability_digest,
        )
        .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredStableV1 {
    schema_version: u32,
    authority_id: [u8; 16],
    principal_id: String,
    lineage_id: [u8; 16],
    profile_id: String,
    profile_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl StoredStableV1 {
    fn from_contract(value: &StableRuntimeBindingV1) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            authority_id: *value.authority_id(),
            principal_id: value.principal_id().to_owned(),
            lineage_id: *value.lineage_id(),
            profile_id: value.profile_id().to_owned(),
            profile_hash: *value.profile_hash(),
            capability_digest: *value.capability_digest(),
        }
    }

    fn into_contract(self) -> Result<StableRuntimeBindingV1, ProtectedBundledRuntimeError> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        StableRuntimeBindingV1::new(
            self.authority_id,
            self.principal_id,
            self.lineage_id,
            self.profile_id,
            self.profile_hash,
            self.capability_digest,
        )
        .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPendingV1 {
    schema_version: u32,
    preparation_id: [u8; 16],
    runtime_root_identity: [u8; 32],
    stable: StoredStableV1,
    executable: StoredExecutableV1,
    profile: StoredProfileV1,
}

impl StoredPendingV1 {
    fn from_contract(value: &PendingFirstActivationV1) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            preparation_id: *value.preparation_id(),
            runtime_root_identity: *value.runtime_root_identity(),
            stable: StoredStableV1::from_contract(value.stable()),
            executable: StoredExecutableV1::from_contract(value.executable()),
            profile: StoredProfileV1::from_contract(value.profile()),
        }
    }

    fn into_contract(self) -> Result<PendingFirstActivationV1, ProtectedBundledRuntimeError> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        PendingFirstActivationV1::new(
            self.preparation_id,
            self.runtime_root_identity,
            self.stable.into_contract()?,
            self.executable.into_contract()?,
            self.profile.into_contract()?,
        )
        .map_err(Into::into)
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct ActivationStateStore {
    directory: PathBuf,
}

#[cfg(unix)]
impl ActivationStateStore {
    fn open(runtime_root: &Path) -> Result<Self, ProtectedBundledRuntimeError> {
        let directory = runtime_root.join(ACTIVATION_STATE_DIRECTORY);
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&directory)
                    .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                    .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            }
            Err(_) => return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
        }
        validate_owner_private_directory(&directory)?;
        Ok(Self { directory })
    }

    fn load_stable(&self) -> Result<Option<StableRuntimeBindingV1>, ProtectedBundledRuntimeError> {
        self.read_record::<StoredStableV1>(STABLE_RECORD_FILE)?
            .map(StoredStableV1::into_contract)
            .transpose()
    }

    fn load_pending(
        &self,
    ) -> Result<Option<PendingFirstActivationV1>, ProtectedBundledRuntimeError> {
        self.read_record::<StoredPendingV1>(PENDING_RECORD_FILE)?
            .map(StoredPendingV1::into_contract)
            .transpose()
    }

    fn persist_stable_exact(
        &self,
        stable: &StableRuntimeBindingV1,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.persist_record_exact(STABLE_RECORD_FILE, &StoredStableV1::from_contract(stable))
    }

    fn persist_pending_exact(
        &self,
        pending: &PendingFirstActivationV1,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.persist_record_exact(
            PENDING_RECORD_FILE,
            &StoredPendingV1::from_contract(pending),
        )
    }

    fn remove_pending(&self) -> Result<(), ProtectedBundledRuntimeError> {
        let path = self.directory.join(PENDING_RECORD_FILE);
        match std::fs::remove_file(path) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn stage_trusted_executable(
        &self,
        source_path: &Path,
        trusted_source: &ExecutableIdentityV1,
    ) -> Result<(PathBuf, ExecutableIdentityV1), ProtectedBundledRuntimeError> {
        let staging_directory = self.directory.join(STAGED_EXECUTABLE_DIRECTORY);
        match std::fs::symlink_metadata(&staging_directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&staging_directory)
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                std::fs::set_permissions(
                    &staging_directory,
                    std::fs::Permissions::from_mode(0o700),
                )
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            }
            Err(_) => return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch),
        }
        validate_owner_private_directory(&staging_directory)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;

        let final_name = format!(
            "{}-{}.gocoded",
            hex::encode(trusted_source.executable_sha256()),
            trusted_source.byte_length()
        );
        let final_path = staging_directory.join(final_name);
        if final_path.exists() {
            validate_staged_executable(&final_path, trusted_source)?;
            let identity = ExecutableIdentityV1::measure(&final_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            return Ok((final_path, identity));
        }

        let temporary_path = staging_directory.join(format!(".{}.tmp", uuid::Uuid::now_v7()));
        let result = (|| {
            let mut source = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(source_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            validate_trusted_source_file(&source)?;
            let source_metadata = source
                .metadata()
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            if source_metadata.len() != trusted_source.byte_length() {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }

            let mut staged = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            let mut digest = Sha256::new();
            let mut length = 0_u64;
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let read = source
                    .read(&mut buffer)
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
                length =
                    length
                        .checked_add(u64::try_from(read).map_err(|_| {
                            ProtectedBundledRuntimeError::ExecutableIdentityMismatch
                        })?)
                        .ok_or(ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                staged
                    .write_all(&buffer[..read])
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            }
            let measured_digest: [u8; 32] = digest.finalize().into();
            if length != trusted_source.byte_length()
                || &measured_digest != trusted_source.executable_sha256()
            {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }
            staged
                .sync_all()
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            std::fs::set_permissions(&temporary_path, std::fs::Permissions::from_mode(0o500))
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            drop(staged);
            match std::fs::hard_link(&temporary_path, &final_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch),
            }
            std::fs::remove_file(&temporary_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            sync_directory(&staging_directory)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            validate_staged_executable(&final_path, trusted_source)?;
            let identity = ExecutableIdentityV1::measure(&final_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            Ok((final_path.clone(), identity))
        })();
        if temporary_path.exists() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        result
    }

    fn read_record<T>(&self, name: &str) -> Result<Option<T>, ProtectedBundledRuntimeError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let path = self.directory.join(name);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
        };
        validate_owner_private_file(&file)?;
        let length = file
            .metadata()
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?
            .len();
        if length == 0 || length > MAX_STATE_BYTES {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        let capacity = usize::try_from(length)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        if bytes.len() as u64 != length {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)
    }

    fn persist_record_exact<T>(
        &self,
        name: &str,
        expected: &T,
    ) -> Result<(), ProtectedBundledRuntimeError>
    where
        T: for<'de> Deserialize<'de> + Eq + Serialize,
    {
        if let Some(existing) = self.read_record::<T>(name)? {
            return if &existing == expected {
                Ok(())
            } else {
                Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
            };
        }

        let encoded = serde_json::to_vec(expected)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        if encoded.is_empty() || encoded.len() as u64 > MAX_STATE_BYTES {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        let temporary_name = format!(".{name}.{}.tmp", uuid::Uuid::now_v7());
        let temporary_path = self.directory.join(temporary_name);
        let final_path = self.directory.join(name);
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary_path)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            file.write_all(&encoded)
                .and_then(|()| file.sync_all())
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            drop(file);
            match std::fs::hard_link(&temporary_path, &final_path) {
                Ok(()) => {
                    std::fs::remove_file(&temporary_path)
                        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
                    sync_directory(&self.directory)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::fs::remove_file(&temporary_path)
                        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
                    let existing = self
                        .read_record::<T>(name)?
                        .ok_or(ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
                    if &existing == expected {
                        Ok(())
                    } else {
                        Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
                    }
                }
                Err(_) => Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
            }
        })();
        if temporary_path.exists() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        result
    }
}

/// Native development/ad-hoc launcher for a protected bundled daemon.
#[derive(Clone)]
pub struct DevelopmentBundledRuntimeLauncher {
    desktop_host_instance_id: [u8; 16],
}

impl fmt::Debug for DevelopmentBundledRuntimeLauncher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevelopmentBundledRuntimeLauncher")
            .field("desktop_host", &"<native-instance>")
            .finish()
    }
}

impl Default for DevelopmentBundledRuntimeLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl DevelopmentBundledRuntimeLauncher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            desktop_host_instance_id: *uuid::Uuid::now_v7().as_bytes(),
        }
    }

    /// Launches one directly measured daemon over an inherited protected
    /// full-duplex channel and waits for exact authenticated readiness.
    ///
    /// # Errors
    ///
    /// Returns a closed failure and reaps the owned child if any admission,
    /// persistence, or readiness check fails.
    pub fn launch(
        &self,
        spec: &ProtectedBundledRuntimeLaunchSpec,
    ) -> Result<ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError> {
        #[cfg(not(unix))]
        {
            let _ = spec;
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(unix)]
        {
            self.launch_unix(spec)
        }
    }

    #[cfg(unix)]
    #[allow(clippy::too_many_lines)]
    fn launch_unix(
        &self,
        spec: &ProtectedBundledRuntimeLaunchSpec,
    ) -> Result<ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError> {
        let executable_path = validate_executable_path(spec.executable())?;
        if executable_path != spec.executable() {
            return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
        }
        let runtime_root = ensure_owner_private_directory(spec.runtime_root())?;
        if runtime_root != spec.runtime_root() {
            return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
        }
        let current_source = ExecutableIdentityV1::measure(&executable_path)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        if &current_source != spec.trusted_source_identity() {
            return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
        }
        let profile = expected_profile()?;
        let state_store = ActivationStateStore::open(&runtime_root)?;
        let (launch_executable_path, executable) = state_store
            .stage_trusted_executable(&executable_path, spec.trusted_source_identity())?;
        let stable = state_store.load_stable()?;
        let pending = state_store.load_pending()?;

        let disposition = match (pending, stable) {
            (Some(pending), stable) => {
                if pending.executable() != &executable
                    || pending.profile() != &profile
                    || stable
                        .as_ref()
                        .is_some_and(|stable| stable != pending.stable())
                {
                    return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
                }
                ActivationDispositionV1::ResumeFirstActivation(Box::new(pending))
            }
            (None, Some(stable)) => {
                if stable.principal_id() != LOCAL_PRINCIPAL
                    || stable.profile_id() != profile.profile_id()
                    || stable.profile_hash() != profile.profile_hash()
                    || stable.capability_digest() != profile.capability_digest()
                {
                    return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
                }
                ActivationDispositionV1::Existing(Box::new(stable))
            }
            (None, None) => ActivationDispositionV1::FirstActivation,
        };

        let issued_at = unix_millis()?;
        let expires_at = issued_at
            .checked_add(
                u64::try_from(LAUNCH_TIMEOUT.as_millis())
                    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?,
            )
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let launch_authority_id = *uuid::Uuid::now_v7().as_bytes();
        let mut secret_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        if secret_bytes == [0; 32] {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(
                LaunchAuthorityError::MissingLaunchAuthority,
            ));
        }
        let secret = LaunchSecret::from_bytes(secret_bytes)?;
        secret_bytes.fill(0);
        let mut request = ProtectedLaunchRequestV1::new(
            launch_authority_id,
            self.desktop_host_instance_id,
            secret,
            issued_at,
            expires_at,
            LOCAL_PRINCIPAL,
            profile,
            executable,
            runtime_root,
            disposition,
        )?;

        let (mut parent_channel, child_channel) = UnixStream::pair()
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        parent_channel
            .set_read_timeout(Some(LAUNCH_TIMEOUT))
            .and_then(|()| parent_channel.set_write_timeout(Some(LAUNCH_TIMEOUT)))
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let child_stdin = Stdio::from(OwnedFd::from(child_channel));
        let child = Command::new(&launch_executable_path)
            .env_clear()
            .stdin(child_stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ProtectedBundledRuntimeError::SpawnFailed)?;
        let mut child = Some(child);

        let result = (|| {
            let spawned_identity = ExecutableIdentityV1::measure(&launch_executable_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            if spawned_identity != *request.executable() {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }
            let launch_frame = Zeroizing::new(
                request
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            );
            write_frame(&mut parent_channel, &launch_frame)?;
            let mut keys = request.derive_keys_and_forget();

            let prepared_pending = if matches!(
                request.activation_disposition(),
                ActivationDispositionV1::FirstActivation
            ) {
                let prepared_frame = read_frame(&mut parent_channel)?;
                let prepared = ProtectedFirstActivationPreparedV1::decode_frame(&prepared_frame)
                    .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?;
                prepared.verify_exact(&request, &keys)?;
                state_store.persist_pending_exact(prepared.pending())?;
                let pending = prepared.pending().clone();
                let mut commit = ProtectedFirstActivationCommitV1::new(
                    request.launch_authority_id(),
                    request.desktop_host_instance_id(),
                    pending.clone(),
                );
                commit.sign(&keys);
                let commit_frame = Zeroizing::new(
                    commit
                        .encode_frame()
                        .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                );
                write_frame(&mut parent_channel, &commit_frame)?;
                Some(pending)
            } else {
                None
            };

            let ready_frame = read_frame(&mut parent_channel)?;
            let ready = ProtectedReadyV1::decode_frame(&ready_frame)
                .map_err(|_| LaunchAuthorityError::ReadinessProofMismatch)?;
            ready.verify_exact(&request, &keys)?;
            if prepared_pending
                .as_ref()
                .is_some_and(|pending| ready.stable() != pending.stable())
            {
                return Err(ProtectedBundledRuntimeError::LaunchAuthority(
                    LaunchAuthorityError::FirstActivationPreparationMismatch,
                ));
            }
            let runtime_profile =
                ProtectedBundledRuntimeProfile::from_ready(&ready, &request, &keys)?;
            keys.forget_bootstrap_key();
            state_store.persist_stable_exact(ready.stable())?;
            state_store.remove_pending()?;
            let owned_launch = ready.owned_launch();
            Ok(ProtectedBundledRuntimeProcess {
                child: child
                    .take()
                    .ok_or(ProtectedBundledRuntimeError::InvalidState)?,
                channel: parent_channel,
                keys,
                request,
                ready,
                owned_launch,
                runtime_profile: Some(runtime_profile),
                renewal_sequence: 0,
                graceful_requested: false,
            })
        })();

        if result.is_err()
            && let Some(child) = child.as_mut()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}

/// Exact child handle, control channel, and authenticated ownership tuple for
/// one desktop-spawned bundled daemon.
pub struct ProtectedBundledRuntimeProcess {
    #[cfg(unix)]
    child: Child,
    #[cfg(unix)]
    channel: UnixStream,
    #[cfg(unix)]
    keys: ProtectedActivationKeys,
    #[cfg(unix)]
    request: ProtectedLaunchRequestV1,
    #[cfg(unix)]
    ready: ProtectedReadyV1,
    #[cfg(unix)]
    owned_launch: ProtectedOwnedLaunchV1,
    runtime_profile: Option<ProtectedBundledRuntimeProfile>,
    renewal_sequence: u64,
    graceful_requested: bool,
}

impl fmt::Debug for ProtectedBundledRuntimeProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBundledRuntimeProcess")
            .field("owned_child", &true)
            .field("renewal_sequence", &self.renewal_sequence)
            .field("protected_fields", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ProtectedBundledRuntimeProcess {
    /// Moves the path-free, one-time bootstrap profile to the native caller.
    pub const fn take_runtime_profile(&mut self) -> Option<ProtectedBundledRuntimeProfile> {
        self.runtime_profile.take()
    }

    /// Confirms that a connected client represents the exact current owned
    /// launch and protected transport.
    #[must_use]
    pub fn matches_client(&self, client: &AuthenticatedRuntimeClient) -> bool {
        #[cfg(not(unix))]
        {
            let _ = client;
            false
        }
        #[cfg(unix)]
        {
            if client.transport_kind() != RuntimeTransportKind::ProtectedBundled {
                return false;
            }
            let session = client.session_info();
            session.profile_id == self.owned_launch.profile().profile_id()
                && session.schema_hash == hex::encode(self.owned_launch.profile().profile_hash())
                && session.authority_id == hex::encode(self.owned_launch.stable().authority_id())
                && session.principal_id == self.owned_launch.stable().principal_id()
                && session.event_log_lineage_id
                    == uuid::Uuid::from_bytes(*self.owned_launch.stable().lineage_id()).to_string()
                && session.daemon_instance_id
                    == uuid::Uuid::from_bytes(*self.owned_launch.daemon_instance_id()).to_string()
                && session.launch_generation == self.owned_launch.launch_generation()
                && session.session_id == hex::encode(self.owned_launch.session_id())
                && session.capability_digest
                    == hex::encode(self.owned_launch.profile().capability_digest())
                && session.certificate_sha256 == hex::encode(self.ready.certificate_sha256())
                && session
                    .capabilities
                    .iter()
                    .map(String::as_str)
                    .eq(REQUIRED_RUNTIME_CAPABILITIES.iter().copied())
        }
    }

    /// Rotates the protected HTTP session without reusing launch authority.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for stale ownership, replay, channel, or ticket
    /// proof failures.
    pub fn renew_profile(
        &mut self,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        #[cfg(not(unix))]
        {
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(unix)]
        {
            if self.graceful_requested {
                return Err(ProtectedBundledRuntimeError::InvalidState);
            }
            let sequence = self
                .renewal_sequence
                .checked_add(1)
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            let mut nonce = [0_u8; 32];
            OsRng.fill_bytes(&mut nonce);
            if nonce == [0; 32] {
                return Err(ProtectedBundledRuntimeError::LaunchAuthority(
                    LaunchAuthorityError::RenewalUnavailable,
                ));
            }
            let mut renewal =
                ProtectedRenewRequestV1::new(self.owned_launch.clone(), sequence, nonce)?;
            nonce.fill(0);
            renewal.sign(&self.keys);
            let renewal_frame = Zeroizing::new(
                renewal
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            );
            write_frame(&mut self.channel, &renewal_frame)?;
            let ticket_frame = read_frame(&mut self.channel)?;
            let ticket = ProtectedRenewTicketV1::decode_frame(&ticket_frame)
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            ticket.verify_exact(&renewal, &self.keys)?;
            let profile = ProtectedBundledRuntimeProfile::from_renewal(
                &self.ready,
                &self.request,
                &renewal,
                &ticket,
                &self.keys,
            )?;
            self.owned_launch = ticket.next_owned_launch();
            self.renewal_sequence = sequence;
            Ok(profile)
        }
    }

    /// Polls only the child handle returned by the direct spawn.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership or platform error if the handle cannot be
    /// observed.
    pub fn status(&mut self) -> Result<BundledRuntimeProcessStatus, ProtectedBundledRuntimeError> {
        #[cfg(not(unix))]
        {
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(unix)]
        {
            self.child
                .try_wait()
                .map(|status| {
                    if status.is_some() {
                        BundledRuntimeProcessStatus::Exited
                    } else {
                        BundledRuntimeProcessStatus::Running
                    }
                })
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
        }
    }

    /// Requests orderly shutdown for the exact current owned launch.
    ///
    /// # Errors
    ///
    /// Returns a closed channel, proof, ownership, or shutdown failure.
    pub fn request_graceful_stop(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        #[cfg(not(unix))]
        {
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(unix)]
        {
            if self.graceful_requested {
                return Ok(());
            }
            let mut shutdown = ProtectedShutdownV1::new(self.owned_launch.clone());
            shutdown.sign(&self.keys);
            let frame = Zeroizing::new(
                shutdown
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            );
            write_frame(&mut self.channel, &frame)?;
            let acknowledgement_frame = read_frame(&mut self.channel)?;
            let acknowledgement = ProtectedShutdownAckV1::decode_frame(&acknowledgement_frame)
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
            acknowledgement.verify_exact(&self.owned_launch, &self.keys)?;
            if !acknowledgement.graceful() {
                return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
            }
            self.graceful_requested = true;
            Ok(())
        }
    }

    /// Waits only for the exact owned child handle.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership or platform error if status cannot be read.
    pub fn wait_for_exit(
        &mut self,
        timeout: Duration,
    ) -> Result<BundledRuntimeProcessStatus, ProtectedBundledRuntimeError> {
        let deadline = Instant::now() + timeout;
        loop {
            let status = self.status()?;
            if status == BundledRuntimeProcessStatus::Exited || Instant::now() >= deadline {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Forces only the process represented by the already-owned child handle.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership or incomplete-shutdown failure.
    pub fn terminate(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        #[cfg(not(unix))]
        {
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(unix)]
        {
            if self.status()? == BundledRuntimeProcessStatus::Exited {
                return Ok(());
            }
            self.child
                .kill()
                .map_err(|_| ProtectedBundledRuntimeError::ShutdownIncomplete)
        }
    }
}

impl Drop for ProtectedBundledRuntimeProcess {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

/// Bounded supervisor for the concrete protected bundled-runtime path.
pub struct ProtectedBundledRuntimeSupervisor {
    launcher: DevelopmentBundledRuntimeLauncher,
    spec: ProtectedBundledRuntimeLaunchSpec,
    process: Option<ProtectedBundledRuntimeProcess>,
    pending_profile: Option<ProtectedBundledRuntimeProfile>,
    backoff: BundledRuntimeBackoff,
    restart_at: Option<Instant>,
    state: BundledRuntimeLifecycleState,
}

impl fmt::Debug for ProtectedBundledRuntimeSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBundledRuntimeSupervisor")
            .field("state", &self.state)
            .field("owned_process", &self.process.is_some())
            .field("pending_profile", &self.pending_profile.is_some())
            .finish_non_exhaustive()
    }
}

impl ProtectedBundledRuntimeSupervisor {
    #[must_use]
    pub fn new(
        launcher: DevelopmentBundledRuntimeLauncher,
        spec: ProtectedBundledRuntimeLaunchSpec,
    ) -> Self {
        Self {
            launcher,
            spec,
            process: None,
            pending_profile: None,
            backoff: BundledRuntimeBackoff::new(),
            restart_at: None,
            state: BundledRuntimeLifecycleState::Absent,
        }
    }

    #[must_use]
    pub const fn state(&self) -> BundledRuntimeLifecycleState {
        self.state
    }

    #[must_use]
    pub const fn owns_runtime(&self) -> bool {
        self.process.is_some()
    }

    /// Starts one fresh protected activation. No external fallback exists.
    ///
    /// # Errors
    ///
    /// Returns a closed launch or lifecycle failure.
    pub fn start(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        if !matches!(
            self.state,
            BundledRuntimeLifecycleState::Absent
                | BundledRuntimeLifecycleState::Stopped
                | BundledRuntimeLifecycleState::FailedStart
                | BundledRuntimeLifecycleState::Exhausted
        ) || self.process.is_some()
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.backoff = BundledRuntimeBackoff::new();
        let result = self.spawn_fresh();
        if result.is_err() {
            self.state = BundledRuntimeLifecycleState::FailedStart;
        }
        result
    }

    fn spawn_fresh(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        self.pending_profile = None;
        self.restart_at = None;
        self.state = BundledRuntimeLifecycleState::ValidatingBinary;
        self.state = BundledRuntimeLifecycleState::Spawning;
        let mut process = self.launcher.launch(&self.spec)?;
        let profile = process
            .take_runtime_profile()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        self.pending_profile = Some(profile);
        self.process = Some(process);
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(())
    }

    /// Moves the current one-time profile to the native `AppCore` integration.
    pub const fn take_runtime_profile(&mut self) -> Option<ProtectedBundledRuntimeProfile> {
        self.pending_profile.take()
    }

    /// Accepts ready only after the protected runtime-client handshake matches
    /// the current exact ownership tuple.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership mismatch for stale or downgraded clients.
    pub fn record_client_ready(
        &mut self,
        client: &AuthenticatedRuntimeClient,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Handshaking
            || self.pending_profile.is_some()
            || !self
                .process
                .as_ref()
                .is_some_and(|process| process.matches_client(client))
        {
            self.state = BundledRuntimeLifecycleState::IdentityMismatch;
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        self.backoff.record_authenticated_ready(Instant::now());
        self.state = BundledRuntimeLifecycleState::Ready;
        Ok(())
    }

    /// Rotates the one-time HTTP session for the currently owned runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, renewal, proof, or channel failure.
    pub fn renew_profile(
        &mut self,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let profile = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .renew_profile()?;
        self.backoff.record_disconnected();
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(profile)
    }

    /// Queues a freshly rotated one-time profile for the native `AppCore`
    /// integration. The previous daemon HTTP session is invalidated before
    /// this method returns.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, renewal, proof, or channel failure.
    pub fn queue_renewal_profile(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        let profile = self.renew_profile()?;
        self.pending_profile = Some(profile);
        Ok(())
    }

    /// Handles a failed HTTP bootstrap without admitting a downgraded mode.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, shutdown, or restart-budget failure.
    pub fn record_client_failure(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        if !matches!(
            self.state,
            BundledRuntimeLifecycleState::Handshaking
                | BundledRuntimeLifecycleState::Ready
                | BundledRuntimeLifecycleState::IdentityMismatch
        ) {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.pending_profile = None;
        if let Some(process) = self.process.as_mut() {
            let _ = process.request_graceful_stop();
            if process.wait_for_exit(Duration::from_secs(1))?
                == BundledRuntimeProcessStatus::Running
            {
                process.terminate()?;
                if process.wait_for_exit(Duration::from_secs(1))?
                    != BundledRuntimeProcessStatus::Exited
                {
                    return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
                }
            }
        }
        self.process = None;
        self.schedule_restart(Instant::now())
    }

    /// Polls the owned child and performs only due bounded fresh activations.
    ///
    /// # Errors
    ///
    /// Returns a closed process, relaunch, or restart-budget failure.
    pub fn monitor(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        if matches!(
            self.state,
            BundledRuntimeLifecycleState::Stopped
                | BundledRuntimeLifecycleState::Absent
                | BundledRuntimeLifecycleState::FailedStart
                | BundledRuntimeLifecycleState::Exhausted
        ) {
            return Ok(());
        }
        let now = Instant::now();
        if self.state == BundledRuntimeLifecycleState::Ready {
            self.backoff.reset_after_stable_readiness(now);
        }
        if self.state == BundledRuntimeLifecycleState::Backoff {
            if self.restart_at.is_some_and(|restart_at| now >= restart_at)
                && let Err(error) = self.spawn_fresh()
            {
                self.process = None;
                self.pending_profile = None;
                self.schedule_restart(now)?;
                return Err(error);
            }
            return Ok(());
        }
        let exited = self
            .process
            .as_mut()
            .map(ProtectedBundledRuntimeProcess::status)
            .transpose()?
            .is_some_and(|status| status == BundledRuntimeProcessStatus::Exited);
        if exited {
            self.process = None;
            self.pending_profile = None;
            self.state = BundledRuntimeLifecycleState::Crashed;
            self.schedule_restart(now)?;
        }
        Ok(())
    }

    fn schedule_restart(&mut self, now: Instant) -> Result<(), ProtectedBundledRuntimeError> {
        self.backoff.record_disconnected();
        match self.backoff.record_unexpected_exit(now) {
            BundledRuntimeRestartDisposition::RestartAfter(delay) => {
                self.restart_at = Some(now + delay);
                self.state = BundledRuntimeLifecycleState::Backoff;
                Ok(())
            }
            BundledRuntimeRestartDisposition::Exhausted => {
                self.restart_at = None;
                self.state = BundledRuntimeLifecycleState::Exhausted;
                Err(ProtectedBundledRuntimeError::RestartExhausted)
            }
        }
    }

    /// Stops only the exact currently owned child. External runtimes are never
    /// represented by this supervisor and therefore cannot be terminated here.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership or incomplete-shutdown failure.
    pub fn stop(&mut self) -> Result<BundledRuntimeStopDisposition, ProtectedBundledRuntimeError> {
        self.restart_at = None;
        self.pending_profile = None;
        self.backoff.record_disconnected();
        let Some(mut process) = self.process.take() else {
            self.state = BundledRuntimeLifecycleState::Stopped;
            return Ok(BundledRuntimeStopDisposition::Graceful);
        };
        self.state = BundledRuntimeLifecycleState::Stopping;
        let graceful_requested = process.request_graceful_stop().is_ok();
        if graceful_requested
            && process.wait_for_exit(BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT)?
                == BundledRuntimeProcessStatus::Exited
        {
            self.state = BundledRuntimeLifecycleState::Stopped;
            return Ok(BundledRuntimeStopDisposition::Graceful);
        }
        process.terminate()?;
        if process.wait_for_exit(BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT)?
            != BundledRuntimeProcessStatus::Exited
        {
            self.process = Some(process);
            return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
        }
        self.state = BundledRuntimeLifecycleState::Stopped;
        Ok(BundledRuntimeStopDisposition::Forced)
    }
}

fn expected_profile() -> Result<ProtectedRuntimeProfileV1, ProtectedBundledRuntimeError> {
    let profile_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::ProfileHashMismatch,
        ))?;
    let capabilities = REQUIRED_RUNTIME_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect::<Vec<_>>();
    ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        gocode_runtime_client::EXPECTED_BUNDLE_ID,
        profile_hash,
        ordered_capability_digest(&capabilities),
    )
    .map_err(Into::into)
}

fn ordered_capability_digest(capabilities: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/local-runtime/capability-digest/v1\0");
    hasher.update(
        u32::try_from(capabilities.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for capability in capabilities {
        let bytes = capability.as_bytes();
        hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

fn unix_millis() -> Result<u64, ProtectedBundledRuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(ProtectedBundledRuntimeError::InvalidState)
}

#[cfg(unix)]
fn read_frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, ProtectedBundledRuntimeError> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|error| map_channel_error(&error))?;
    let payload_length = u32::from_be_bytes(prefix) as usize;
    if payload_length == 0 || payload_length > MAX_FRAME_PAYLOAD_BYTES {
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::InvalidContract,
        ));
    }
    let total =
        payload_length
            .checked_add(4)
            .ok_or(ProtectedBundledRuntimeError::LaunchAuthority(
                LaunchAuthorityError::InvalidContract,
            ))?;
    let mut frame = Zeroizing::new(vec![0_u8; total]);
    frame[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|error| map_channel_error(&error))?;
    Ok(frame)
}

#[cfg(unix)]
fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), ProtectedBundledRuntimeError> {
    if frame.len() < 5 || frame.len() > MAX_FRAME_PAYLOAD_BYTES + 4 {
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::InvalidContract,
        ));
    }
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|error| map_channel_error(&error))
}

#[cfg(unix)]
fn map_channel_error(error: &std::io::Error) -> ProtectedBundledRuntimeError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        ProtectedBundledRuntimeError::ReadinessTimeout
    } else {
        ProtectedBundledRuntimeError::ProtectedChannelUnavailable
    }
}

#[cfg(unix)]
fn validate_executable_path(path: &Path) -> Result<PathBuf, ProtectedBundledRuntimeError> {
    if !path.is_absolute() {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    let original = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    if original.file_type().is_symlink() || !original.is_file() {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || metadata.len() == 0 || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    validate_secure_directory_chain(&canonical)?;
    Ok(canonical)
}

#[cfg(unix)]
fn validate_secure_directory_chain(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    let effective_uid = rustix::process::geteuid().as_raw();
    let mut child_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    let mut directory = path
        .parent()
        .ok_or(ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    loop {
        let metadata = std::fs::symlink_metadata(directory)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        {
            return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
        }
        if mode & 0o022 != 0
            && (mode & 0o1000 == 0
                || (child_metadata.uid() != 0 && child_metadata.uid() != effective_uid))
        {
            return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
        }
        child_metadata = metadata;
        let Some(parent) = directory.parent() else {
            break;
        };
        if parent == directory {
            break;
        }
        directory = parent;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_source_file(file: &File) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || metadata.len() == 0 || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_staged_executable(
    path: &Path,
    trusted_source: &ExecutableIdentityV1,
) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o500
        || metadata.nlink() != 1
        || metadata.len() != trusted_source.byte_length()
    {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    let identity = ExecutableIdentityV1::measure(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if identity.executable_sha256() != trusted_source.executable_sha256()
        || identity.byte_length() != trusted_source.byte_length()
    {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_owner_private_directory(path: &Path) -> Result<PathBuf, ProtectedBundledRuntimeError> {
    if !path.is_absolute() {
        return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        }
        Err(_) => return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable),
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
    }
    std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    validate_owner_private_directory(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    Ok(canonical)
}

#[cfg(unix)]
fn validate_owner_private_directory(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owner_private_file(file: &File) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn executable(path: &Path, mode: u32) {
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").expect("write executable fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set executable permissions");
    }

    fn stable() -> StableRuntimeBindingV1 {
        let profile = expected_profile().expect("expected profile");
        StableRuntimeBindingV1::new(
            *uuid::Uuid::now_v7().as_bytes(),
            LOCAL_PRINCIPAL,
            *uuid::Uuid::now_v7().as_bytes(),
            profile.profile_id(),
            *profile.profile_hash(),
            *profile.capability_digest(),
        )
        .expect("stable binding")
    }

    #[test]
    fn launch_spec_rejects_relative_symlink_and_writable_executables() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let runtime_root = temporary.path().join("runtime");
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(Path::new("relative-gocoded"), &runtime_root,),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );

        let writable = temporary.path().join("writable-gocoded");
        executable(&writable, 0o777);
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(&writable, &runtime_root),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );

        let target = temporary.path().join("target-gocoded");
        executable(&target, 0o755);
        let link = temporary.path().join("linked-gocoded");
        std::os::unix::fs::symlink(&target, &link).expect("create executable symlink");
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(&link, &runtime_root),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );

        let writable_parent = temporary.path().join("writable-parent");
        std::fs::create_dir(&writable_parent).expect("create writable parent");
        std::fs::set_permissions(&writable_parent, std::fs::Permissions::from_mode(0o777))
            .expect("weaken parent permissions");
        let unsafe_daemon = writable_parent.join("gocoded");
        executable(&unsafe_daemon, 0o755);
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(&unsafe_daemon, &runtime_root),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );
    }

    #[test]
    fn launch_rejects_source_replacement_after_identity_is_pinned() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let daemon = temporary.path().join("gocoded");
        executable(&daemon, 0o755);
        let spec =
            ProtectedBundledRuntimeLaunchSpec::new(&daemon, &temporary.path().join("runtime"))
                .expect("trusted launch spec");
        std::fs::write(&daemon, b"#!/bin/sh\nexit 7\n").expect("replace source bytes");
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o755))
            .expect("restore executable permissions");

        assert_eq!(
            DevelopmentBundledRuntimeLauncher::new()
                .launch(&spec)
                .expect_err("replacement must fail before protected admission"),
            ProtectedBundledRuntimeError::ExecutableIdentityMismatch
        );
    }

    #[test]
    fn discovery_uses_only_colocated_absolute_executable() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let desktop = temporary.path().join("gocode-desktop");
        let daemon = temporary.path().join("gocoded");
        executable(&desktop, 0o755);
        executable(&daemon, 0o755);

        assert_eq!(
            discover_bundled_runtime(&desktop).expect("discover protected daemon"),
            std::fs::canonicalize(&daemon).expect("canonical daemon")
        );

        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o775))
            .expect("weaken daemon permissions");
        assert_eq!(
            discover_bundled_runtime(&desktop),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );
    }

    #[test]
    fn activation_records_are_exact_owner_private_and_non_secret() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect runtime root");
        let store = ActivationStateStore::open(temporary.path()).expect("state store");
        let expected_stable = stable();
        store
            .persist_stable_exact(&expected_stable)
            .expect("persist stable");
        assert_eq!(
            store.load_stable().expect("load stable"),
            Some(expected_stable)
        );

        let path = store.directory.join(STABLE_RECORD_FILE);
        let bytes = std::fs::read(&path).expect("read stable record");
        let text = String::from_utf8(bytes).expect("stable JSON");
        assert!(!text.contains("launch_secret"));
        assert!(!text.contains("bootstrap"));
        assert!(!text.contains("credential"));
        assert_eq!(
            std::fs::metadata(path)
                .expect("stable metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&store.directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let different = stable();
        assert_eq!(
            store.persist_stable_exact(&different),
            Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
        );
    }

    #[test]
    fn activation_record_with_weakened_acl_is_rejected() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect runtime root");
        let store = ActivationStateStore::open(temporary.path()).expect("state store");
        store
            .persist_stable_exact(&stable())
            .expect("persist stable");
        let path = store.directory.join(STABLE_RECORD_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("weaken stable permissions");
        assert_eq!(
            store.load_stable(),
            Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
        );
    }

    #[test]
    fn concrete_supervisor_exhausts_the_bounded_restart_budget() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let daemon = temporary.path().join("gocoded");
        executable(&daemon, 0o755);
        let spec =
            ProtectedBundledRuntimeLaunchSpec::new(&daemon, &temporary.path().join("runtime"))
                .expect("launch spec");
        let mut supervisor =
            ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
        let now = Instant::now();

        for _ in 0..5 {
            supervisor
                .schedule_restart(now)
                .expect("restart remains available");
            assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Backoff);
        }
        assert_eq!(
            supervisor.schedule_restart(now),
            Err(ProtectedBundledRuntimeError::RestartExhausted)
        );
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Exhausted);
    }
}
