//! Owner-only durable command witnesses; never replays a pending mutation.
use super::pending::Pending;
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, flock, fsync, openat, unlinkat};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::AsRawFd,
    path::{Component, Path},
};
const LIMIT: u64 = 128 * 1024;
pub(super) struct Journal {
    directory: rustix::fd::OwnedFd,
    scope: String,
}
impl Journal {
    pub fn open(state: &Path, scope: String) -> Result<Self, String> {
        if !state.is_absolute() {
            return Err("Invalid journal directory".into());
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
                    fd = crate::open_directory(
                        &fd,
                        name.to_str().ok_or("Invalid journal directory")?,
                        true,
                        false,
                    )
                    .map_err(|_| "Journal directory unavailable")?
                    .ok_or("Journal directory unavailable")?;
                    crate::validate_ancestor_directory(&fd)
                        .map_err(|_| "Insecure journal directory")?;
                }
                _ => return Err("Invalid journal directory".into()),
            }
        }
        for name in ["runne", "cli", "chat-intents", &scope] {
            fd = crate::open_directory(&fd, name, true, true)
                .map_err(|_| "Journal directory unavailable")?
                .ok_or("Journal directory unavailable")?;
        }
        flock(&fd, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "Another terminal client owns this project's pending-command journal")?;
        Ok(Self {
            directory: fd,
            scope,
        })
    }
    pub fn pending(&self) -> Result<Vec<Pending>, String> {
        let mut result = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
            .map_err(error)?
            .take(17)
        {
            let name = entry.map_err(error)?.file_name();
            let name = name.to_str().ok_or("Invalid pending command record")?;
            let id = name
                .strip_suffix(".json")
                .ok_or("Invalid pending command record")?;
            let id = runne_runtime_client::CanonicalId::parse(id)
                .map_err(|_| "Invalid pending command identity")?;
            let fd = openat(
                &self.directory,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(error)?;
            let stat = rustix::fs::fstat(&fd).map_err(error)?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || stat.st_mode & 0o7777 != 0o600
                || stat.st_nlink != 1
                || stat.st_size < 0
                || u64::try_from(stat.st_size).map_or(true, |size| size > LIMIT)
            {
                return Err("Insecure pending command record".into());
            }
            let mut bytes = Vec::new();
            File::from(fd)
                .take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(error)?;
            if bytes.len() as u64 > LIMIT {
                return Err("Pending command record too large".into());
            }
            let record: Pending =
                serde_json::from_slice(&bytes).map_err(|_| "Invalid pending command record")?;
            if record.version != 1 || record.scope != self.scope || record.command != id {
                return Err("Pending command scope mismatch".into());
            }
            record.witness()?;
            result.push(record);
        }
        if result.len() > 16 {
            return Err("Too many unresolved terminal commands".into());
        }
        Ok(result)
    }
    pub fn save(&self, record: &Pending) -> Result<(), String> {
        if record.scope != self.scope {
            return Err("Pending command scope mismatch".into());
        }
        let bytes = serde_json::to_vec(record).map_err(error)?;
        if bytes.len() as u64 > LIMIT {
            return Err("Pending command record too large".into());
        }
        let fd = openat(
            &self.directory,
            format!("{}.json", record.command),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(error)?;
        let mut file = File::from(fd);
        file.write_all(&bytes).map_err(error)?;
        file.sync_all().map_err(error)?;
        fsync(&self.directory).map_err(error)
    }
    pub fn resolved(&self, record: &Pending) -> Result<(), String> {
        unlinkat(
            &self.directory,
            format!("{}.json", record.command),
            AtFlags::empty(),
        )
        .map_err(error)?;
        fsync(&self.directory).map_err(error)
    }
}
fn error(_: impl std::fmt::Display) -> String {
    "Terminal command journal unavailable".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_witness_survives_reopen_and_scope_cannot_be_rebound() {
        let home = dirs::home_dir().unwrap();
        let root = tempfile::tempdir_in(home).unwrap();
        let workspace = runne_runtime_client::CanonicalId::now_v7();
        let pending = Pending::new(
            &crate::permissions_tests::session_info(),
            workspace,
            runne_runtime_client::CanonicalId::now_v7(),
            Some("日本語\nmultiline".into()),
            None,
        );
        let journal = Journal::open(root.path(), pending.scope.clone()).unwrap();
        journal.save(&pending).unwrap();
        assert!(Journal::open(root.path(), pending.scope.clone()).is_err());
        drop(journal);
        let journal = Journal::open(root.path(), pending.scope.clone()).unwrap();
        let recovered = journal.pending().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].command, pending.command);
        assert_eq!(recovered[0].prompt, pending.prompt);
        let mut wrong = recovered[0].clone();
        wrong.scope = "wrong".into();
        assert!(journal.save(&wrong).is_err());
        journal.resolved(&recovered[0]).unwrap();
        assert!(journal.pending().unwrap().is_empty());
    }
}
