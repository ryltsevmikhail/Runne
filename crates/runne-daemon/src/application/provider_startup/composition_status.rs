//! Non-authoritative, closed startup status. Publication never changes admission.
#[cfg(target_os = "linux")]
pub(super) fn publish(database: &str, stage: &'static str) {
    let _ = publish_checked(std::path::Path::new(database), stage);
}
#[cfg(not(target_os = "linux"))]
pub(super) fn publish(_: &str, _: &'static str) {}
#[cfg(target_os = "linux")]
fn publish_checked(database: &std::path::Path, stage: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::{fs::OpenOptions, io};
    // Values originate only in the adjacent closed classification function.
    if stage.len() > 64
        || !stage.starts_with("provider_compose_")
        || !stage.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
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
    if !directory.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::other("private directory required"));
    }
    let anchored =
        std::path::PathBuf::from(format!("/proc/self/fd/{}", directory_file.as_raw_fd()));
    let directory = anchored.as_path();
    let destination = directory.join("provider-startup-status");
    if let Ok(meta) = destination.symlink_metadata()
        && (!meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1)
    {
        return Err(io::Error::other("private status required"));
    }
    let temporary = directory.join(format!(".provider-startup-{}.tmp", uuid::Uuid::now_v7()));
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
    fn status_is_bounded_private_and_replaced_per_attempt() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.path().join("event-log.db");
        publish_checked(&database, "provider_compose_pending").unwrap();
        publish_checked(&database, "provider_compose_journal_key").unwrap();
        let status = root.path().join("provider-startup-status");
        assert_eq!(
            std::fs::read_to_string(&status).unwrap(),
            "provider_compose_journal_key"
        );
        assert_eq!(
            std::fs::metadata(&status).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(publish_checked(&database, "provider_compose_secret/path").is_err());
        publish_checked(&database, "provider_compose_ready").unwrap();
        assert_eq!(
            std::fs::read_to_string(&status).unwrap(),
            "provider_compose_ready"
        );
    }
    #[test]
    fn status_rejects_symlink_and_broad_file_mode() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.path().join("event-log.db");
        let target = root.path().join("target");
        std::fs::write(&target, b"unchanged").unwrap();
        let status = root.path().join("provider-startup-status");
        symlink(&target, &status).unwrap();
        assert!(publish_checked(&database, "provider_compose_ready").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
        std::fs::remove_file(&status).unwrap();
        std::fs::write(&status, b"unchanged").unwrap();
        std::fs::set_permissions(&status, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(publish_checked(&database, "provider_compose_ready").is_err());
    }
}
