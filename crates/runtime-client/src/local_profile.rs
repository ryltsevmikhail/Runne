//! Protected local profile loading for privileged native clients.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::{
    AuthenticatedRuntimeClient, HttpRuntimeClient, RuntimeApiError, RuntimeCredential,
    RuntimeEndpoint, RuntimeProfile, RuntimeTransportError,
};

const LOCAL_PROFILE_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_PROFILE_BYTES: usize = 16 * 1024;
const TOKEN_BYTES: usize = 32;

/// Fail-closed protected-profile loading error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LocalProfileError {
    #[error("local runtime profile is unavailable")]
    Unavailable,
    #[error("local runtime profile permissions are insecure")]
    InsecurePermissions,
    #[error("local runtime profile is invalid")]
    InvalidProfile,
    #[error("local runtime credential is invalid")]
    InvalidCredential,
}

/// Failure while constructing and authenticating the local runtime client.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LocalRuntimeConnectError {
    #[error("local runtime transport is unavailable")]
    Transport(#[from] RuntimeTransportError),
    #[error("local runtime authentication failed")]
    Api(#[from] RuntimeApiError),
}

/// Exact local endpoint/profile plus a host-only credential.
///
/// Debug output intentionally omits the credential and token path.
pub struct LocalRuntimeProfile {
    profile: RuntimeProfile,
    credential: RuntimeCredential,
}

impl fmt::Debug for LocalRuntimeProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRuntimeProfile")
            .field("endpoint", &self.profile.endpoint())
            .field("credential", &"<redacted>")
            .finish()
    }
}

impl LocalRuntimeProfile {
    /// Loads an exact owner-only profile and its separate 32-byte credential.
    ///
    /// On Unix both files must be regular, non-symlink files with no group or
    /// other permission bits and must belong to the effective process user.
    /// Other platforms fail closed until native owner ACL validation exists.
    /// Unknown JSON fields and non-loopback endpoints are rejected.
    ///
    /// # Errors
    ///
    /// Returns a redacted typed failure without retaining filesystem paths or
    /// credential bytes.
    pub fn load(path: &Path) -> Result<Self, LocalProfileError> {
        let profile_bytes = read_secure_file(
            path,
            MAXIMUM_PROFILE_BYTES,
            LocalProfileError::InvalidProfile,
        )?;
        let wire: LocalProfileWire = serde_json::from_slice(&profile_bytes)
            .map_err(|_| LocalProfileError::InvalidProfile)?;
        if wire.schema_version != LOCAL_PROFILE_SCHEMA_VERSION || !wire.token_path.is_absolute() {
            return Err(LocalProfileError::InvalidProfile);
        }
        let address = wire
            .endpoint
            .parse()
            .map_err(|_| LocalProfileError::InvalidProfile)?;
        let endpoint =
            RuntimeEndpoint::loopback(address).map_err(|_| LocalProfileError::InvalidProfile)?;
        let profile = RuntimeProfile::validate(endpoint, &wire.profile_id, &wire.schema_hash)
            .map_err(|_| LocalProfileError::InvalidProfile)?;
        let credential_bytes = read_secure_file(
            &wire.token_path,
            TOKEN_BYTES,
            LocalProfileError::InvalidCredential,
        )?;
        let credential: [u8; TOKEN_BYTES] = credential_bytes
            .try_into()
            .map_err(|_| LocalProfileError::InvalidCredential)?;
        Ok(Self {
            profile,
            credential: RuntimeCredential::from_bytes(credential),
        })
    }

    /// Returns the validated loopback endpoint without exposing credentials.
    #[must_use]
    pub const fn endpoint(&self) -> RuntimeEndpoint {
        self.profile.endpoint()
    }

    /// Builds the bounded HTTP client and completes the exact authenticated
    /// profile handshake.
    ///
    /// # Errors
    ///
    /// Returns a typed transport or authenticated API failure.
    pub async fn connect(
        self,
        timeout: Duration,
    ) -> Result<AuthenticatedRuntimeClient, LocalRuntimeConnectError> {
        let client = HttpRuntimeClient::new(self.profile, timeout)?;
        Ok(client.authenticate(self.credential).await?)
    }
}

/// Resolves the standard daemon-owned local profile location.
///
/// # Errors
///
/// Returns `Unavailable` when no platform runtime/data directory can be
/// resolved.
pub fn default_local_profile_path() -> Result<PathBuf, LocalProfileError> {
    let root = dirs::runtime_dir()
        .or_else(dirs::data_local_dir)
        .or_else(|| dirs::home_dir().map(|home| home.join(".local").join("share")))
        .ok_or(LocalProfileError::Unavailable)?;
    Ok(root.join("gocode-daemon").join("client-profile.json"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalProfileWire {
    schema_version: u32,
    profile_id: String,
    schema_hash: String,
    endpoint: String,
    token_path: PathBuf,
}

fn read_secure_file(
    path: &Path,
    maximum_bytes: usize,
    invalid_content: LocalProfileError,
) -> Result<Vec<u8>, LocalProfileError> {
    let mut file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalProfileError::Unavailable)?;
    if !metadata.is_file() {
        return Err(invalid_content);
    }
    ensure_owner_only(&metadata)?;
    let maximum_length =
        u64::try_from(maximum_bytes).map_err(|_| LocalProfileError::Unavailable)?;
    if metadata.len() > maximum_length {
        return Err(invalid_content);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| LocalProfileError::Unavailable)?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|_| LocalProfileError::Unavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(invalid_content);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, LocalProfileError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| LocalProfileError::Unavailable)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, LocalProfileError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| LocalProfileError::Unavailable)
}

#[cfg(unix)]
fn ensure_owner_only(metadata: &std::fs::Metadata) -> Result<(), LocalProfileError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let effective_user = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective_user || metadata.permissions().mode() & 0o077 != 0 {
        return Err(LocalProfileError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only(_: &std::fs::Metadata) -> Result<(), LocalProfileError> {
    Err(LocalProfileError::InsecurePermissions)
}
