//! PROPOSAL (D1.2 item 5.1 — owner decision required): Linux equivalent of the
//! macOS `enrollment_profile_directory` derivation.
//!
//! macOS derives the enrollment profile directory as `runtime_root.parent()`
//! (`host.rs::enrollment_profile_directory`). The Linux desktop already builds
//! the identical layout: `BundledRuntimeController::discover` receives
//! `profile_directory.join("bundled-runtime")` where `profile_directory` is the
//! Tauri `app_data_dir()` (`$XDG_DATA_HOME/com.runne.desktop`,
//! `apps/desktop/src-tauri/src/lib_parts/run.rs`), and the updater journals
//! live at `profile_directory/updates/`
//! (`apps/desktop/src-tauri/src/updater_status.rs`).
//!
//! This module is a PROPOSAL prototype only: it is compiled exclusively under
//! `test` + `desktop-protected` + `target_os = "linux"` and is NOT wired into
//! the enrollment transition composition. Integration happens only after the
//! owner accepts (or amends) the variant.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Leaf directory name of the bundled runtime inside the profile directory.
///
/// `#[allow]` is intentional: this is a PROPOSAL prototype awaiting the owner's
/// D1.2 item 5.1 decision; production wiring lands only after acceptance.
#[allow(dead_code)]
const BUNDLED_RUNTIME_LEAF: &str = "bundled-runtime";

/// PROPOSAL (variant C): derive the Linux enrollment profile directory from the
/// daemon-owned runtime root, enforcing the desktop layout contract.
///
/// Mirrors the macOS `runtime_root.parent()` mapping and adds two structural
/// invariants so a silently drifted layout fails closed (returns `None`, which
/// degrades to the current no-anchor behaviour) instead of pointing the
/// enrollment verifier at an unrelated directory:
///
/// 1. the runtime root leaf must be exactly `bundled-runtime`;
/// 2. the parent must exist and be a directory.
///
/// Journal content is intentionally NOT checked here: the downstream
/// `VerifiedDaemonNativeEnrollmentPrepare` verification revalidates the
/// updater journals inside the returned directory, so derivation stays a pure
/// structural mapping.
///
/// `#[allow]` is intentional: PROPOSAL prototype awaiting the owner's D1.2
/// item 5.1 decision; production wiring lands only after acceptance.
#[allow(dead_code)]
#[must_use]
pub(crate) fn enrollment_profile_directory(runtime_root: &Path) -> Option<PathBuf> {
    if runtime_root.file_name() != Some(OsStr::new(BUNDLED_RUNTIME_LEAF)) {
        return None;
    }
    let profile_directory = runtime_root.parent()?;
    if !profile_directory.is_dir() {
        return None;
    }
    Some(profile_directory.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::enrollment_profile_directory;
    use std::fs;
    use std::path::Path;

    fn profile_layout(temporary: &Path) -> (PathBuf, PathBuf) {
        let profile_directory = temporary.join("com.runne.desktop");
        let runtime_root = profile_directory.join("bundled-runtime");
        fs::create_dir_all(&runtime_root).expect("layout created");
        (profile_directory, runtime_root)
    }

    use std::path::PathBuf;

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
        let runtime_root = Path::new("/nonexistent-runne-proposal")
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
