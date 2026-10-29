//! Durable identities for registration prefixes; the runtime still owns every mutation.
use runne_runtime_client::{CanonicalId, CommandIdentity, RuntimeSessionInfo};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, fsync, openat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    version: u8,
    scope: String,
    pub project: CanonicalId,
    pub workspace: CanonicalId,
    project_command: CanonicalId,
    workspace_command: CanonicalId,
    pub label: String,
}
impl Intent {
    pub fn project_identity(&self) -> Result<CommandIdentity, String> {
        identity(self.project_command)
    }
    pub fn workspace_identity(&self) -> Result<CommandIdentity, String> {
        identity(self.workspace_command)
    }
}
fn identity(id: CanonicalId) -> Result<CommandIdentity, String> {
    CommandIdentity::new(id, format!("terminal-registration:{id}")).map_err(error)
}
pub(super) fn scope(session: &RuntimeSessionInfo, root: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"runne:terminal-registration:v1");
    for part in [
        &session.authority_id,
        &session.event_log_lineage_id,
        &session.principal_id,
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.update(root);
    hex::encode(hash.finalize())
}
pub(super) struct Journal {
    directory: rustix::fd::OwnedFd,
    scope: String,
}
impl Journal {
    pub fn open(state: &Path, scope: String) -> Result<Self, String> {
        if !state.is_absolute()
            || scope.len() != 64
            || !scope.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("Invalid registration journal scope".into());
        }
        let mut fd = openat(
            rustix::fs::CWD,
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(error)?;
        for component in state.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    fd = crate::directory_scope::open_directory(
                        &fd,
                        name.to_str().ok_or("Invalid state path")?,
                        true,
                        false,
                    )
                    .map_err(|_| "Registration state unavailable")?
                    .ok_or("Registration state unavailable")?;
                    crate::directory_scope::validate_ancestor_directory(&fd)
                        .map_err(|_| "Insecure registration state")?;
                }
                _ => return Err("Invalid state path".into()),
            }
        }
        for name in ["runne", "cli", "registration-intents", &scope] {
            fd = crate::directory_scope::open_directory(&fd, name, true, true)
                .map_err(|_| "Registration journal unavailable")?
                .ok_or("Registration journal unavailable")?;
        }
        flock(&fd, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "Registration is already in progress")?;
        Ok(Self {
            directory: fd,
            scope,
        })
    }
    pub fn load_or_create(&self, label: &str) -> Result<Intent, String> {
        let fd = match openat(
            &self.directory,
            "intent.json",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => {
                let intent = Intent {
                    version: 1,
                    scope: self.scope.clone(),
                    project: CanonicalId::now_v7(),
                    workspace: CanonicalId::now_v7(),
                    project_command: CanonicalId::now_v7(),
                    workspace_command: CanonicalId::now_v7(),
                    label: label.into(),
                };
                self.publish(&intent)?;
                return Ok(intent);
            }
            Err(e) => return Err(error(e)),
        };
        let stat = rustix::fs::fstat(&fd).map_err(error)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || stat.st_size < 0
            || stat.st_size > 8192
        {
            return Err("Insecure registration intent".into());
        }
        let mut bytes = Vec::new();
        File::from(fd)
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(error)?;
        let value: Intent = serde_json::from_slice(&bytes).map_err(error)?;
        if value.version != 1
            || value.scope != self.scope
            || value.label.is_empty()
            || value.label.len() > 255
        {
            return Err("Registration intent scope mismatch".into());
        }
        value.project_identity()?;
        value.workspace_identity()?;
        Ok(value)
    }
    fn publish(&self, intent: &Intent) -> Result<(), String> {
        let bytes = serde_json::to_vec(intent).map_err(error)?;
        if bytes.len() > 8192 {
            return Err("Registration intent too large".into());
        }
        let temp = format!("{}.tmp", CanonicalId::now_v7());
        let fd = openat(
            &self.directory,
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(error)?;
        let mut file = File::from(fd);
        file.write_all(&bytes).map_err(error)?;
        file.sync_all().map_err(error)?;
        rustix::fs::renameat_with(
            &self.directory,
            &temp,
            &self.directory,
            "intent.json",
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(error)?;
        fsync(&self.directory).map_err(error)
    }
}
fn error(_: impl std::fmt::Display) -> String {
    "Registration intent unavailable; retain it and retry /register".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_prefix_reopens_same_resource_and_command_ids_at_every_ack_boundary() {
        let home = dirs::home_dir().unwrap();
        let root = tempfile::tempdir_in(home).unwrap();
        let scope = "a".repeat(64);
        let original = Journal::open(root.path(), scope.clone())
            .unwrap()
            .load_or_create("Project")
            .unwrap();
        // Before the first POST, after lost project ACK, and after lost workspace ACK.
        for _boundary in 0..3 {
            let reopened = Journal::open(root.path(), scope.clone())
                .unwrap()
                .load_or_create("Renamed label")
                .unwrap();
            assert_eq!(original, reopened);
        }
        let changed = Journal::open(root.path(), "b".repeat(64))
            .unwrap()
            .load_or_create("Project")
            .unwrap();
        assert_ne!(original.project, changed.project);
    }
}
