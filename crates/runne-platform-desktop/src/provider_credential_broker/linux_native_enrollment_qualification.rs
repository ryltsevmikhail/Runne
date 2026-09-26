//! Narrow opt-in transport for the signed Linux enrollment qualification hook.

use std::path::{Path, PathBuf};

pub const FIXTURE_ROOT_ENV: &str = "RUNNE_D1_1B_POST_DELETE_KILL_FIXTURE_ROOT";

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
}
