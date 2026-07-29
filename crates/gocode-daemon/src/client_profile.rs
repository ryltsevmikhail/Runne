//! Owner-only local client profile publication.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::DaemonError;

const CLIENT_PROFILE_SCHEMA_VERSION: u32 = 1;
#[allow(dead_code)]
pub(crate) const LOCAL_RUNTIME_PROFILE_V2: &str = "gocode-local-runtime/2";

/// Strict inactive profile-v2 wire representation for pinned TLS clients.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
pub(crate) struct ClientProfileV2Wire {
    schema_version: u32,
    transport_profile_id: String,
    profile_id: String,
    schema_hash: String,
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

#[allow(dead_code)]
impl ClientProfileV2Wire {
    /// Serializes the exact profile-v2 wire shape. Publication remains inactive until Task 4.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        endpoint: SocketAddr,
        certificate_der_base64: String,
        certificate_sha256: [u8; 32],
        bootstrap_secret_path: PathBuf,
        authority_id: [u8; 16],
        event_log_lineage_id: uuid::Uuid,
        daemon_instance_id: uuid::Uuid,
        launch_generation: u64,
    ) -> Result<Self, DaemonError> {
        if !bootstrap_secret_path.is_absolute() || launch_generation == 0 {
            return Err(DaemonError::Bootstrap("invalid profile-v2 identity".into()));
        }
        Ok(Self {
            schema_version: 2,
            transport_profile_id: LOCAL_RUNTIME_PROFILE_V2.to_owned(),
            profile_id: gocode_runtime::bundle::BUNDLE_ID.to_owned(),
            schema_hash: gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH.to_owned(),
            capability_digest: gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH.to_owned(),
            endpoint: format!("https://{endpoint}"),
            certificate_der_base64,
            certificate_sha256: hex::encode(certificate_sha256),
            bootstrap_secret_path,
            authority_id: hex::encode(authority_id),
            principal_id: "local-owner".to_owned(),
            event_log_lineage_id: event_log_lineage_id.to_string(),
            daemon_instance_id: daemon_instance_id.to_string(),
            launch_generation,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientProfileWire<'a> {
    schema_version: u32,
    profile_id: &'static str,
    schema_hash: &'static str,
    endpoint: String,
    token_path: &'a Path,
}

/// Lifetime guard for the exact connection profile published by this daemon.
pub(crate) struct PublishedClientProfile {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl PublishedClientProfile {
    /// Publishes a token-reference profile beside the protected daemon token.
    ///
    /// Replacement is atomic on Unix. Other platforms still use a
    /// same-directory temporary file; current clients fail closed there until
    /// native owner ACL validation exists.
    pub(crate) fn publish(token_path: &Path, endpoint: SocketAddr) -> Result<Self, DaemonError> {
        let directory = token_path.parent().ok_or_else(|| {
            DaemonError::Bootstrap("token path has no profile directory".to_owned())
        })?;
        let path = directory.join("client-profile.json");
        let bytes = serde_json::to_vec(&ClientProfileWire {
            schema_version: CLIENT_PROFILE_SCHEMA_VERSION,
            profile_id: gocode_runtime::bundle::BUNDLE_ID,
            schema_hash: gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH,
            endpoint: endpoint.to_string(),
            token_path,
        })
        .map_err(|_| DaemonError::Bootstrap("serialize local client profile".to_owned()))?;
        let temporary = directory.join(format!(".client-profile.{}.tmp", uuid::Uuid::now_v7()));
        if let Err(error) = write_owner_only(&temporary, &bytes)
            .and_then(|()| replace_profile(&temporary, &path))
            .and_then(|()| sync_directory(directory))
        {
            let _ = fs::remove_file(&temporary);
            return Err(DaemonError::Bootstrap(format!(
                "publish local client profile: {error}"
            )));
        }
        Ok(Self { path, bytes })
    }
}

impl Drop for PublishedClientProfile {
    fn drop(&mut self) {
        let matches_this_instance = fs::read(&self.path)
            .map(|current| current == self.bytes)
            .unwrap_or(false);
        if matches_this_instance {
            let _ = fs::remove_file(&self.path);
            if let Some(directory) = self.path.parent() {
                let _ = sync_directory(directory);
            }
        }
    }
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let mut file = file;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(windows))]
fn replace_profile(temporary: &Path, target: &Path) -> std::io::Result<()> {
    fs::rename(temporary, target)
}

#[cfg(windows)]
fn replace_profile(temporary: &Path, target: &Path) -> std::io::Result<()> {
    match fs::remove_file(target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(temporary, target)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> std::io::Result<()> {
    Ok(())
}
