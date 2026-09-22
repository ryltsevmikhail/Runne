//! PROPOSAL variant C, integrated (D1.2 items 5.1 + 5.2 — owner accepted for
//! the integration candidate): Linux equivalent of the macOS
//! `enrollment_profile_directory` derivation.
//!
//! macOS derives the enrollment profile directory as `runtime_root.parent()`
//! (`host/mod.rs::enrollment_profile_directory`). The Linux desktop already
//! builds the identical layout: `BundledRuntimeController::discover` receives
//! `profile_directory.join("bundled-runtime")` where `profile_directory` is the
//! Tauri `app_data_dir()` (`apps/desktop/src-tauri/src/lib_parts/run.rs`), and
//! the updater journals live at `profile_directory/updates/`
//! (`apps/desktop/src-tauri/src/updater_status.rs`).
//!
//! Provenance of `runtime_root` on Linux: the desktop produces it through
//! `ProtectedBundledRuntimeLaunchSpec::new`, which resolves the directory with
//! `ensure_owner_private_directory` (symlink-rejecting `symlink_metadata`
//! check, canonicalization, `uid == euid`, mode `0700`). The derivation below
//! therefore re-verifies the same owner-private invariants on the *parent*
//! instead of trusting a bare `.is_dir()` stat (which follows symlinks and
//! proves nothing about ownership):
//!
//! 1. the runtime root leaf must be exactly `bundled-runtime`;
//! 2. the parent must exist as a real directory (not a symlink);
//! 3. the parent must be owned by the effective uid and mode `0700`.
//!
//! Any failure returns `None` and degrades to the current no-anchor
//! fail-closed behaviour. Journal content is intentionally NOT checked here:
//! the downstream enrollment verification revalidates the updater journals
//! inside the returned directory, so derivation stays a pure structural
//! mapping and no signature or permission check is weakened or duplicated.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Leaf directory name of the bundled runtime inside the profile directory.
const BUNDLED_RUNTIME_LEAF: &str = "bundled-runtime";

/// Derives the Linux enrollment profile directory from the daemon-owned
/// runtime root, enforcing the desktop layout contract and the owner-private
/// invariants guaranteed by the desktop-side launch spec.
///
/// Mirrors the macOS `runtime_root.parent()` mapping; a silently drifted
/// layout fails closed (returns `None`, which degrades to the no-anchor
/// behaviour) instead of pointing the enrollment verifier at an unrelated
/// directory.
#[must_use]
pub(crate) fn enrollment_profile_directory(runtime_root: &Path) -> Option<PathBuf> {
    if runtime_root.file_name() != Some(OsStr::new(BUNDLED_RUNTIME_LEAF)) {
        return None;
    }
    let profile_directory = runtime_root.parent()?;
    match std::fs::symlink_metadata(profile_directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => None,
        Ok(metadata) => {
            if metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return None;
            }
            Some(profile_directory.to_path_buf())
        }
        Err(_) => None,
    }
}

#[cfg(all(test, feature = "desktop-protected", target_os = "linux"))]
mod tests {
    use super::enrollment_profile_directory;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    fn profile_layout(temporary: &Path) -> (PathBuf, PathBuf) {
        let profile_directory = temporary.join("com.runne.desktop");
        let runtime_root = profile_directory.join("bundled-runtime");
        fs::create_dir_all(&runtime_root).expect("layout created");
        fs::set_permissions(&profile_directory, fs::Permissions::from_mode(0o700))
            .expect("profile mode set");
        (profile_directory, runtime_root)
    }

    #[test]
    fn mirrors_macos_runtime_root_parent_mapping() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let (profile_directory, runtime_root) = profile_layout(temporary.path());
        assert_eq!(
            enrollment_profile_directory(&runtime_root),
            Some(profile_directory)
        );
    }

    #[test]
    fn rejects_runtime_root_without_bundled_runtime_leaf() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let elsewhere = temporary.path().join("com.runne.desktop");
        let runtime_root = elsewhere.join("runtime-v2");
        fs::create_dir_all(&runtime_root).expect("layout created");
        assert_eq!(enrollment_profile_directory(&runtime_root), None);
    }

    #[test]
    fn rejects_missing_profile_directory() {
        let runtime_root = Path::new("/nonexistent-runne-enrollment-51")
            .join("com.runne.desktop")
            .join("bundled-runtime");
        assert_eq!(enrollment_profile_directory(&runtime_root), None);
    }

    #[test]
    fn rejects_file_parent() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let parent = temporary.path().join("not-a-directory");
        fs::write(&parent, b"regular file").expect("file written");
        let runtime_root = parent.join("bundled-runtime");
        assert_eq!(enrollment_profile_directory(&runtime_root), None);
    }

    #[test]
    fn rejects_runtime_root_without_parent() {
        assert_eq!(
            enrollment_profile_directory(Path::new("bundled-runtime")),
            None
        );
    }

    #[test]
    fn rejects_symlinked_profile_directory() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let real = temporary.path().join("real-profile");
        fs::create_dir_all(real.join("bundled-runtime")).expect("layout created");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("mode set");
        let link = temporary.path().join("com.runne.desktop");
        std::os::unix::fs::symlink(&real, &link).expect("symlink created");
        assert_eq!(
            enrollment_profile_directory(&link.join("bundled-runtime")),
            None
        );
    }

    #[test]
    fn rejects_group_or_world_accessible_profile_directory() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let (profile_directory, runtime_root) = profile_layout(temporary.path());
        fs::set_permissions(&profile_directory, fs::Permissions::from_mode(0o755))
            .expect("loose mode set");
        assert_eq!(enrollment_profile_directory(&runtime_root), None);
    }

    #[test]
    fn derivation_is_structural_and_ignores_journal_presence() {
        // Journal content validation belongs to the downstream native
        // verification; a profile directory without journals still derives.
        let temporary = tempfile::tempdir().expect("tempdir");
        let (profile_directory, runtime_root) = profile_layout(temporary.path());
        assert!(!profile_directory.join("updates").exists());
        assert_eq!(
            enrollment_profile_directory(&runtime_root),
            Some(profile_directory)
        );
    }
}
