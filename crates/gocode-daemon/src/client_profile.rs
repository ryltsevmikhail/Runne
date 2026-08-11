//! Owner-only local client profile publication.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::DaemonError;
use crate::launch_identity::LaunchIdentity;

pub(crate) const LOCAL_RUNTIME_PROFILE_V2: &str = "gocode-local-runtime/2";

/// Strict profile-v2 wire representation for pinned TLS clients.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ClientProfileV2Wire {
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

impl ClientProfileV2Wire {
    /// Serializes the exact profile-v2 wire shape.
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
        capabilities: &[&str],
    ) -> Result<Self, DaemonError> {
        if !bootstrap_secret_path.is_absolute() || launch_generation == 0 {
            return Err(DaemonError::Bootstrap("invalid profile-v2 identity".into()));
        }
        Ok(Self {
            schema_version: 2,
            transport_profile_id: LOCAL_RUNTIME_PROFILE_V2.to_owned(),
            profile_id: gocode_runtime::bundle::BUNDLE_ID.to_owned(),
            schema_hash: gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH.to_owned(),
            capabilities: capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
            capability_digest: hex::encode(
                gocode_http::runtime_profile::ordered_capability_digest(capabilities),
            ),
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

/// Lifetime guard for one active v2 profile and its bootstrap secret.
pub(crate) struct PublishedClientProfileV2 {
    profile_path: PathBuf,
    profile_bytes: Vec<u8>,
    secret_path: PathBuf,
    secret_bytes: [u8; 32],
}

impl PublishedClientProfileV2 {
    pub(crate) fn publish(
        directory: &Path,
        endpoint: SocketAddr,
        identity: &LaunchIdentity,
        authority_id: [u8; 16],
        lineage_id: uuid::Uuid,
        capabilities: &[&str],
    ) -> Result<Self, DaemonError> {
        let directory = std::fs::canonicalize(directory)
            .map_err(|_| DaemonError::Bootstrap("canonicalize v2 profile directory".into()))?;
        let secret_path = directory.join(format!(
            "bootstrap-{}.secret",
            identity.daemon_instance_id()
        ));
        identity
            .write_bootstrap_secret(&secret_path)
            .map_err(|_| DaemonError::Bootstrap("write v2 bootstrap secret".into()))?;
        let secret_bytes: [u8; 32] = fs::read(&secret_path)
            .map_err(|_| DaemonError::Bootstrap("read v2 bootstrap secret".into()))?
            .try_into()
            .map_err(|_| DaemonError::Bootstrap("invalid v2 bootstrap secret".into()))?;
        let wire = ClientProfileV2Wire::new(
            endpoint,
            identity.profile_certificate_der_base64(),
            *identity.certificate_sha256(),
            secret_path.clone(),
            authority_id,
            lineage_id,
            uuid::Uuid::from_bytes(identity.daemon_instance_id().into_bytes()),
            identity.launch_generation(),
            capabilities,
        )?;
        let profile_bytes = serde_json::to_vec(&wire)
            .map_err(|_| DaemonError::Bootstrap("serialize v2 profile".into()))?;
        let profile_path = directory.join("client-profile.json");
        let temporary = directory.join(format!(".client-profile.{}.tmp", uuid::Uuid::now_v7()));
        if let Err(error) = write_owner_only(&temporary, &profile_bytes)
            .and_then(|()| replace_profile(&temporary, &profile_path))
            .and_then(|()| sync_directory(&directory))
        {
            let _ = fs::remove_file(&temporary);
            remove_if_matches(&profile_path, &profile_bytes);
            remove_if_matches(&secret_path, &secret_bytes);
            let _ = sync_directory(&directory);
            return Err(DaemonError::Bootstrap(format!(
                "publish v2 local client profile: {error}"
            )));
        }
        Ok(Self {
            profile_path,
            profile_bytes,
            secret_path,
            secret_bytes,
        })
    }
}

fn remove_if_matches(path: &Path, bytes: &[u8]) {
    if fs::read(path)
        .map(|current| current == bytes)
        .unwrap_or(false)
    {
        let _ = fs::remove_file(path);
    }
}

impl Drop for PublishedClientProfileV2 {
    fn drop(&mut self) {
        for (path, bytes) in [
            (&self.profile_path, self.profile_bytes.as_slice()),
            (&self.secret_path, self.secret_bytes.as_slice()),
        ] {
            if fs::read(path)
                .map(|current| current == bytes)
                .unwrap_or(false)
            {
                let _ = fs::remove_file(path);
            }
        }
        self.secret_bytes.zeroize();
        self.profile_bytes.zeroize();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_profile_and_published_files_exclude_private_key_marker() {
        let directory = tempfile::tempdir().unwrap();
        let (identity, marker) =
            LaunchIdentity::generate_with_private_key_marker_for_test(1).unwrap();
        let published = PublishedClientProfileV2::publish(
            directory.path(),
            "127.0.0.1:3000".parse().unwrap(),
            &identity,
            [1; 16],
            uuid::Uuid::now_v7(),
            gocode_runtime::bundle::BASE_RUNTIME_CAPABILITIES,
        )
        .unwrap();
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(marker.len()).any(|part| part == marker));
        }
        let profile: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("client-profile.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            profile["capabilities"],
            serde_json::json!(gocode_runtime::bundle::BASE_RUNTIME_CAPABILITIES)
        );
        drop(published);
    }
}
