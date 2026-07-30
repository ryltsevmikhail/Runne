//! Protected local profile loading for privileged native clients.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AuthenticatedRuntimeClient, GOLDEN_BUNDLE_HASH, REQUIRED_RUNTIME_CAPABILITIES, RuntimeEndpoint,
};

const LOCAL_PROFILE_SCHEMA_VERSION: u32 = 2;
const LOCAL_TRANSPORT_PROFILE_ID: &str = "gocode-local-runtime/2";
const MAXIMUM_PROFILE_BYTES: usize = 16 * 1024;
const MAXIMUM_CERTIFICATE_BYTES: usize = 16 * 1024;

/// Fail-closed protected-profile loading error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LocalProfileError {
    #[error("local runtime profile is unavailable")]
    Unavailable,
    #[error("local runtime profile permissions are insecure")]
    InsecurePermissions,
    #[error("local runtime profile is incompatible")]
    InvalidProfile,
    #[error("local runtime credential is invalid")]
    InvalidCredential,
}

/// Failure while constructing and authenticating the local runtime client.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LocalRuntimeConnectError {
    #[error("local runtime transport is unavailable")]
    Transport(#[from] crate::RuntimeTransportError),
    #[error("local runtime authentication failed")]
    Api(#[from] crate::RuntimeApiError),
}

/// Exact peer identity and authority tuple for one local daemon launch.
///
/// The bootstrap secret is intentionally not read by `load`.
pub struct LocalRuntimeProfile {
    pub(crate) endpoint: RuntimeEndpoint,
    pub(crate) origin: String,
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) certificate_sha256: [u8; 32],
    pub(crate) bootstrap_secret_path: PathBuf,
    pub(crate) authority_id: [u8; 16],
    pub(crate) principal_id: String,
    pub(crate) event_log_lineage_id: uuid::Uuid,
    pub(crate) daemon_instance_id: uuid::Uuid,
    pub(crate) launch_generation: u64,
    pub(crate) schema_hash: [u8; 32],
    pub(crate) capabilities: Vec<String>,
    pub(crate) capability_digest: [u8; 32],
}

impl fmt::Debug for LocalRuntimeProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRuntimeProfile")
            .field("endpoint", &self.endpoint)
            .field("transport", &LOCAL_TRANSPORT_PROFILE_ID)
            .field("peer_identity", &"<pinned>")
            .finish_non_exhaustive()
    }
}

impl LocalRuntimeProfile {
    /// Loads one strict owner-only profile v2 without reading its bootstrap secret.
    ///
    /// On Unix the profile must be a regular, non-symlink file owned by the
    /// effective user with exact mode `0600`. Other platforms fail closed until
    /// native no-reparse owner ACL validation is available.
    ///
    /// # Errors
    ///
    /// Returns a redacted incompatibility for profile v1 and a redacted invalid
    /// profile error for every other malformed or untrusted value.
    pub fn load(path: &Path) -> Result<Self, LocalProfileError> {
        let profile_bytes = read_secure_file(
            path,
            MAXIMUM_PROFILE_BYTES,
            LocalProfileError::InvalidProfile,
        )?;
        if schema_version(&profile_bytes) == Some(1) {
            return Err(LocalProfileError::InvalidProfile);
        }
        let wire: LocalProfileV2Wire = serde_json::from_slice(&profile_bytes)
            .map_err(|_| LocalProfileError::InvalidProfile)?;
        if wire.schema_version != LOCAL_PROFILE_SCHEMA_VERSION
            || wire.transport_profile_id != LOCAL_TRANSPORT_PROFILE_ID
            || wire.profile_id != crate::EXPECTED_BUNDLE_ID
            || wire.schema_hash != GOLDEN_BUNDLE_HASH
            || wire.launch_generation == 0
            || !wire.bootstrap_secret_path.is_absolute()
        {
            return Err(LocalProfileError::InvalidProfile);
        }

        let (endpoint, origin) = parse_endpoint(&wire.endpoint)?;
        let certificate_der = STANDARD
            .decode(&wire.certificate_der_base64)
            .map_err(|_| LocalProfileError::InvalidProfile)?;
        if certificate_der.is_empty() || certificate_der.len() > MAXIMUM_CERTIFICATE_BYTES {
            return Err(LocalProfileError::InvalidProfile);
        }
        let certificate_sha256 = decode_lower_hex_32(&wire.certificate_sha256)?;
        if Sha256::digest(&certificate_der).as_slice() != certificate_sha256 {
            return Err(LocalProfileError::InvalidProfile);
        }
        let schema_hash = decode_lower_hex_32(&wire.schema_hash)?;
        let capability_digest = decode_lower_hex_32(&wire.capability_digest)?;
        if wire.capabilities.is_empty()
            || wire.capabilities.iter().any(|capability| {
                capability.is_empty()
                    || capability.len() > 256
                    || capability.chars().any(char::is_control)
            })
            || ordered_capability_digest(&wire.capabilities) != capability_digest
        {
            return Err(LocalProfileError::InvalidProfile);
        }
        let authority_id = decode_lower_hex_16(&wire.authority_id)?;
        validate_uuid_v7(uuid::Uuid::from_bytes(authority_id))?;
        if wire.principal_id.is_empty()
            || wire.principal_id.len() > 256
            || wire.principal_id.chars().any(char::is_control)
        {
            return Err(LocalProfileError::InvalidProfile);
        }
        let event_log_lineage_id = parse_uuid_v7(&wire.event_log_lineage_id)?;
        let daemon_instance_id = parse_uuid_v7(&wire.daemon_instance_id)?;
        if !wire
            .capabilities
            .iter()
            .map(String::as_str)
            .eq(REQUIRED_RUNTIME_CAPABILITIES.iter().copied())
        {
            return Err(LocalProfileError::InvalidProfile);
        }

        Ok(Self {
            endpoint,
            origin,
            certificate_der,
            certificate_sha256,
            bootstrap_secret_path: wire.bootstrap_secret_path,
            authority_id,
            principal_id: wire.principal_id,
            event_log_lineage_id,
            daemon_instance_id,
            launch_generation: wire.launch_generation,
            schema_hash,
            capabilities: wire.capabilities,
            capability_digest,
        })
    }

    /// Returns the validated loopback endpoint without exposing credentials.
    #[must_use]
    pub const fn endpoint(&self) -> RuntimeEndpoint {
        self.endpoint
    }

    /// Verifies pinned TLS, proves the bootstrap secret, and opens one session.
    ///
    /// # Errors
    ///
    /// No bootstrap secret or protected content is read or sent before the
    /// profile-pinned TLS peer has answered the challenge request.
    pub async fn connect(
        self,
        timeout: Duration,
    ) -> Result<AuthenticatedRuntimeClient, LocalRuntimeConnectError> {
        crate::local_session::connect(self, timeout).await
    }
}

/// Resolves the standard daemon-owned local profile location.
///
/// # Errors
///
/// Returns `Unavailable` when no platform runtime/data directory can be resolved.
pub fn default_local_profile_path() -> Result<PathBuf, LocalProfileError> {
    let root = dirs::runtime_dir()
        .or_else(dirs::data_local_dir)
        .or_else(|| dirs::home_dir().map(|home| home.join(".local").join("share")))
        .ok_or(LocalProfileError::Unavailable)?;
    Ok(root.join("gocode-daemon").join("client-profile.json"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalProfileV2Wire {
    schema_version: u32,
    transport_profile_id: String,
    profile_id: String,
    schema_hash: String,
    capabilities: Vec<String>,
    capability_digest: String,
    endpoint: String,
    certificate_der_base64: String,
    certificate_sha256: String,
    bootstrap_secret_path: PathBuf,
    authority_id: String,
    principal_id: String,
    event_log_lineage_id: String,
    daemon_instance_id: String,
    launch_generation: u64,
}

fn schema_version(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("schemaVersion")?
        .as_u64()
}

fn parse_endpoint(value: &str) -> Result<(RuntimeEndpoint, String), LocalProfileError> {
    let url: reqwest::Url = value
        .parse()
        .map_err(|_| LocalProfileError::InvalidProfile)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(LocalProfileError::InvalidProfile);
    }
    let ip = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .ok_or(LocalProfileError::InvalidProfile)?;
    if !ip.is_loopback() {
        return Err(LocalProfileError::InvalidProfile);
    }
    let port = url.port().ok_or(LocalProfileError::InvalidProfile)?;
    let address = SocketAddr::new(ip, port);
    let endpoint =
        RuntimeEndpoint::loopback(address).map_err(|_| LocalProfileError::InvalidProfile)?;
    Ok((endpoint, format!("https://{address}")))
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], LocalProfileError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LocalProfileError::InvalidProfile);
    }
    let mut output = [0; 32];
    hex::decode_to_slice(value, &mut output).map_err(|_| LocalProfileError::InvalidProfile)?;
    Ok(output)
}

fn decode_lower_hex_16(value: &str) -> Result<[u8; 16], LocalProfileError> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LocalProfileError::InvalidProfile);
    }
    let mut output = [0; 16];
    hex::decode_to_slice(value, &mut output).map_err(|_| LocalProfileError::InvalidProfile)?;
    Ok(output)
}

fn parse_uuid_v7(value: &str) -> Result<uuid::Uuid, LocalProfileError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| LocalProfileError::InvalidProfile)?;
    validate_uuid_v7(parsed)?;
    if parsed.to_string() != value {
        return Err(LocalProfileError::InvalidProfile);
    }
    Ok(parsed)
}

fn validate_uuid_v7(value: uuid::Uuid) -> Result<(), LocalProfileError> {
    if value.get_version_num() != 7 || value.get_variant() != uuid::Variant::RFC4122 {
        return Err(LocalProfileError::InvalidProfile);
    }
    Ok(())
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

pub fn read_bootstrap_secret(path: &Path) -> Result<[u8; 32], LocalRuntimeConnectError> {
    let bytes = read_secure_file(path, 32, LocalProfileError::InvalidCredential)
        .map_err(|_| incompatible())?;
    bytes.try_into().map_err(|_| incompatible())
}

const fn incompatible() -> LocalRuntimeConnectError {
    LocalRuntimeConnectError::Api(crate::RuntimeApiError::new(
        crate::RuntimeApiErrorKind::Incompatible,
    ))
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
    if metadata.uid() != effective_user || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(LocalProfileError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only(_: &std::fs::Metadata) -> Result<(), LocalProfileError> {
    Err(LocalProfileError::InsecurePermissions)
}
