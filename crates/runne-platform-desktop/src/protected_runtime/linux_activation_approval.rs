//! Owner-only, one-shot publication for the opt-in Linux enrollment record.
use runne_api::provider_credential_enrollment::linux_activation_policy::{
    ACTIVATION_RECORD_FILE, LinuxEnrollmentActivationRecord,
};
use rustix::fs::{Mode, OFlags, RenameFlags, fchmod, fstat, open, openat, renameat_with};
use std::io::Write as _;
use std::{os::fd::AsRawFd as _, path::Path};

/// Closed publication failures; detailed OS errors stay native and private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxActivationApprovalPublishError {
    InvalidRuntimeRoot,
    RecordExistsOrStale,
    PublicationFailed,
}

impl std::fmt::Display for LinuxActivationApprovalPublishError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Linux activation record publication denied")
    }
}

impl std::error::Error for LinuxActivationApprovalPublishError {}

/// Publishes one already measured record without following paths or replacing anything.
///
/// # Errors
///
/// Returns a closed error when the runtime root is unsafe, a record or stale
/// temporary file already exists, or the atomic durable publication fails.
pub fn publish_linux_activation_record(
    runtime_root: &Path,
    record: &LinuxEnrollmentActivationRecord,
) -> Result<(), LinuxActivationApprovalPublishError> {
    use LinuxActivationApprovalPublishError as Failure;

    let canonical = runtime_root
        .canonicalize()
        .map_err(|_| Failure::InvalidRuntimeRoot)?;
    if canonical != runtime_root {
        return Err(Failure::InvalidRuntimeRoot);
    }
    let root = open(
        runtime_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Failure::InvalidRuntimeRoot)?;
    let metadata = fstat(&root).map_err(|_| Failure::InvalidRuntimeRoot)?;
    let root_via_fd = Path::new("/proc/self/fd").join(root.as_raw_fd().to_string());
    if metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o700
        || root_via_fd.canonicalize().ok().as_deref() != Some(canonical.as_path())
    {
        return Err(Failure::InvalidRuntimeRoot);
    }
    let file = openat(
        &root,
        ".linux-enrollment-activation.tmp",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            Failure::RecordExistsOrStale
        } else {
            Failure::PublicationFailed
        }
    })?;
    fchmod(&file, Mode::from_raw_mode(0o600)).map_err(|_| Failure::PublicationFailed)?;
    let mut file = std::fs::File::from(file);
    if file.write_all(record.to_config_json().as_bytes()).is_err() || file.sync_all().is_err() {
        return Err(Failure::PublicationFailed);
    }
    renameat_with(
        &root,
        ".linux-enrollment-activation.tmp",
        &root,
        ACTIVATION_RECORD_FILE,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            Failure::RecordExistsOrStale
        } else {
            Failure::PublicationFailed
        }
    })?;
    std::fs::File::from(root)
        .sync_all()
        .map_err(|_| Failure::PublicationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_api::provider_credential_enrollment::linux_activation_policy::LinuxEnrollmentScope;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn record() -> LinuxEnrollmentActivationRecord {
        LinuxEnrollmentActivationRecord {
            provider_scope: LinuxEnrollmentScope::Catalog,
            runtime_root_digest: [1; 32],
            desktop_image_digest: [2; 32],
            writer_image_digest: [3; 32],
            daemon_image_digest: [4; 32],
            runtime_authority_id: [5; 16],
            machine_id_digest: [6; 32],
            approved_at_unix_millis: 1,
        }
    }

    #[test]
    fn creates_private_record_and_refuses_second_publication() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        publish_linux_activation_record(dir.path(), &record()).unwrap();
        let target = dir.path().join(ACTIVATION_RECORD_FILE);
        let metadata = std::fs::metadata(&target).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        let bytes = std::fs::read(&target).unwrap();
        assert!(publish_linux_activation_record(dir.path(), &record()).is_err());
        assert_eq!(std::fs::read(target).unwrap(), bytes);
    }

    #[test]
    fn refuses_non_private_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(publish_linux_activation_record(dir.path(), &record()).is_err());
    }

    #[test]
    fn refuses_private_root_with_special_mode_bits() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o2700)).unwrap();
        assert!(publish_linux_activation_record(dir.path(), &record()).is_err());
    }
}
