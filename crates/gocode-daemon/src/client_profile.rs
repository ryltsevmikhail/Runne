//! Owner-only local client profile publication.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::DaemonError;

const CLIENT_PROFILE_SCHEMA_VERSION: u32 = 1;

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
