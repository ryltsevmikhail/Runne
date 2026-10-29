//! Scoped non-authoritative diagnostics for public effects projection.
use std::{cell::RefCell, path::PathBuf};
thread_local! { static CURRENT: RefCell<Option<State>> = const { RefCell::new(None) }; }
struct State {
    database: PathBuf,
    failure: Option<&'static str>,
    succeeded: bool,
}
pub(crate) struct Scope {
    previous: Option<State>,
}
impl Scope {
    pub(crate) fn new(database: Option<&str>) -> Self {
        let state = database.filter(|path| !path.is_empty()).map(|path| State {
            database: PathBuf::from(path),
            failure: None,
            succeeded: false,
        });
        if let Some(state) = &state {
            publish(&state.database, "effects.pending");
        }
        let previous = CURRENT.with(|current| current.replace(state));
        Self { previous }
    }
    pub(crate) fn succeeded(&self) {
        CURRENT.with(|current| {
            if let Some(state) = current.borrow_mut().as_mut() {
                state.succeeded = true;
            }
        });
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let state = CURRENT.with(|current| current.replace(self.previous.take()));
        if let Some(state) = state {
            publish(
                &state.database,
                state.failure.unwrap_or(if state.succeeded {
                    "effects.ready"
                } else {
                    "effects.unclassified"
                }),
            );
        }
    }
}
pub(super) fn record(stage: &'static str) {
    CURRENT.with(|current| {
        if let Some(state) = current.borrow_mut().as_mut() {
            state.failure.get_or_insert(stage);
        }
    });
}
#[cfg(target_os = "linux")]
fn publish(database: &std::path::Path, stage: &'static str) {
    let _ = publish_checked(database, stage);
}
#[cfg(not(target_os = "linux"))]
fn publish(_: &std::path::Path, _: &'static str) {}
#[cfg(target_os = "linux")]
fn publish_checked(database: &std::path::Path, stage: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::{fs::OpenOptions, io};
    // Values originate only in the adjacent closed classification function.
    if stage.len() > 64
        || !super::ALLOWED.contains(&stage)
            && !["effects.pending", "effects.ready", "effects.unclassified"].contains(&stage)
        || !stage
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.')
    {
        return Err(io::Error::other("invalid status"));
    }
    let directory = database
        .parent()
        .ok_or_else(|| io::Error::other("no directory"))?;
    let directory_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(directory)?;
    let metadata = directory_file.metadata()?;
    let owner = effective_uid()?;
    if !directory.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::other("private directory required"));
    }
    let anchored =
        std::path::PathBuf::from(format!("/proc/self/fd/{}", directory_file.as_raw_fd()));
    let directory = anchored.as_path();
    let destination = directory.join("provider-effects-status");
    if let Ok(meta) = destination.symlink_metadata()
        && (!meta.is_file()
            || meta.uid() != owner
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1)
    {
        return Err(io::Error::other("private status required"));
    }
    let temporary = directory.join(format!(".provider-effects-{}.tmp", uuid::Uuid::now_v7()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(stage.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, &destination)?;
        directory_file.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn scope_retains_first_closed_failure_and_clears_on_success() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.path().join("event-log.db");
        let status = root.path().join("provider-effects-status");
        {
            let _scope = Scope::new(database.to_str());
            super::super::record("remote.attempt_missing");
            super::super::record("effects.remote_snapshot");
        }
        assert_eq!(
            std::fs::read_to_string(&status).unwrap(),
            "remote.attempt_missing"
        );
        {
            let scope = Scope::new(database.to_str());
            scope.succeeded();
        }
        assert_eq!(std::fs::read_to_string(&status).unwrap(), "effects.ready");
        {
            let _scope = Scope::new(database.to_str());
        }
        assert_eq!(
            std::fs::read_to_string(&status).unwrap(),
            "effects.unclassified"
        );
        assert!(publish_checked(&database, "secret/path").is_err());
        std::fs::remove_file(&status).unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, "unchanged").unwrap();
        symlink(&target, &status).unwrap();
        assert!(publish_checked(&database, "effects.ready").is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
    }
}

#[cfg(target_os = "linux")]
fn effective_uid() -> std::io::Result<u32> {
    use std::io::Read;
    let mut status = String::new();
    std::fs::File::open("/proc/self/status")?
        .take(16 * 1024)
        .read_to_string(&mut status)?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().nth(1))
        .and_then(|uid| uid.parse().ok())
        .ok_or_else(|| std::io::Error::other("process owner unavailable"))
}
