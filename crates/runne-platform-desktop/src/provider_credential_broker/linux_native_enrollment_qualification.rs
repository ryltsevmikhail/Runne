//! Narrow opt-in transport for the signed Linux enrollment qualification hook.

use std::path::{Path, PathBuf};

pub const FIXTURE_ROOT_ENV: &str = "RUNNE_D1_1B_POST_DELETE_KILL_FIXTURE_ROOT";
const DIAGNOSTIC_FILE: &str = "linux-enrollment-stage.log";

/// Records one fixed native Linux enrollment stage when qualification logging is opted in.
///
/// Unknown stage names are ignored so this interface cannot become a payload log.
pub fn record_enrollment_stage(stage: &'static str) {
    const ALLOWED: &[&str] = &[
        "resource_hint_missing",
        "writer_capability_begin",
        "writer_capability_ready",
        "writer_capability_failed",
        "measurement_begin",
        "measurement_ready",
        "measurement_failed",
        "transition_begin",
        "transition_ready",
        "transition_failed",
        "profile_install_ready",
        "profile_install_failed",
        "capability_profile_runtime",
        "capability_peer_paths",
        "capability_policy",
        "capability_trust",
        "capability_admission",
        "capability_identity",
        "capability_refresh",
        "capability_peer_recheck",
        "capability_revalidate_policy",
        "capability_revalidate_trust",
        "capability_revalidate_time",
        "capability_revalidate_admission",
        "capability_artifact",
        "capability_measurement",
        "capability_measurement_facts",
    ];
    if !ALLOWED.contains(&stage) {
        return;
    }
    let Ok(Some(root)) = fixture_root_from_env() else {
        return;
    };
    append_diagnostic(&root, stage);
}

fn append_diagnostic(root: &Path, stage: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let path = root.join(DIAGNOSTIC_FILE);
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
    else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() >= 65_536
    {
        return;
    }
    let _ = writeln!(file, "stage={stage}");
    let _ = file.sync_data();
}

#[derive(Debug)]
pub struct QualificationFixtureError;

/// Reads and validates the private owner-controlled fixture root, if opted in.
///
/// # Errors
///
/// Returns an error when the supplied root is not canonical, private, and owner-controlled.
pub fn fixture_root_from_env() -> Result<Option<PathBuf>, QualificationFixtureError> {
    let Some(root) = std::env::var_os(FIXTURE_ROOT_ENV) else {
        return Ok(None);
    };
    validate_fixture_root(Path::new(&root)).map(Some)
}

/// Validates the same exact owner/private-directory constraint at each process boundary.
///
/// # Errors
///
/// Returns an error unless both the canonical root and its parent are private owner directories.
pub fn validate_fixture_root(root: &Path) -> Result<PathBuf, QualificationFixtureError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !root.is_absolute() {
        return Err(QualificationFixtureError);
    }
    let canonical = std::fs::canonicalize(root).map_err(|_| QualificationFixtureError)?;
    if canonical != root {
        return Err(QualificationFixtureError);
    }
    let root_metadata = std::fs::symlink_metadata(root).map_err(|_| QualificationFixtureError)?;
    let parent = root.parent().ok_or(QualificationFixtureError)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| QualificationFixtureError)?;
    let owner = rustix::process::geteuid().as_raw();
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || root_metadata.uid() != owner
        || parent_metadata.uid() != owner
        || root_metadata.permissions().mode() & 0o077 != 0
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(QualificationFixtureError);
    }
    Ok(canonical)
}

/// Forwards only the validated fixture path across the desktop's `env_clear` boundary.
///
/// # Errors
///
/// Returns an error when an opted-in root fails path or permission validation.
pub fn forward_fixture_root(
    command: &mut std::process::Command,
) -> Result<(), QualificationFixtureError> {
    if let Some(root) = fixture_root_from_env()? {
        command.env(FIXTURE_ROOT_ENV, root);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn accepts_private_canonical_root_and_rejects_loose_or_linked_roots() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.path().join("fixture");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(validate_fixture_root(&root).unwrap(), root);

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_fixture_root(&root).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert!(validate_fixture_root(&link).is_err());
    }

    #[test]
    fn rejects_public_parent_directory() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = parent.path().join("fixture");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_fixture_root(&root).is_err());
    }

    #[test]
    fn diagnostic_append_rejects_symlink_fifo_and_special_mode_files() {
        use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.path().join("fixture");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        let target = root.join("target");
        std::fs::write(&target, b"").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, root.join(DIAGNOSTIC_FILE)).unwrap();
        append_diagnostic(&root, "measurement_ready");
        assert_eq!(std::fs::read(&target).unwrap(), b"");
        std::fs::remove_file(root.join(DIAGNOSTIC_FILE)).unwrap();

        let root_fd = rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        rustix::fs::mkfifoat(
            &root_fd,
            root.join(DIAGNOSTIC_FILE),
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        append_diagnostic(&root, "measurement_ready");
        assert!(
            std::fs::symlink_metadata(root.join(DIAGNOSTIC_FILE))
                .unwrap()
                .file_type()
                .is_fifo()
        );
        std::fs::remove_file(root.join(DIAGNOSTIC_FILE)).unwrap();

        std::fs::write(root.join(DIAGNOSTIC_FILE), b"").unwrap();
        std::fs::set_permissions(
            root.join(DIAGNOSTIC_FILE),
            std::fs::Permissions::from_mode(0o2600),
        )
        .unwrap();
        append_diagnostic(&root, "measurement_ready");
        assert_eq!(std::fs::read(root.join(DIAGNOSTIC_FILE)).unwrap(), b"");
    }
}
