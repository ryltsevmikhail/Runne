//! Platform-owned installation of a verified staged desktop package.

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

use crate::{StagedUpdate, UpdateArtifactKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum NativeUpdateInstallError {
    #[error("staged update artifact is invalid")]
    InvalidArtifact,
    #[error("update installer is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("native update installer failed")]
    InstallerFailed,
}

/// Installs one already verified artifact without exposing paths to the renderer.
pub fn install_staged_update(
    update: &StagedUpdate,
    current_executable: &Path,
) -> Result<(), NativeUpdateInstallError> {
    if !is_regular_file(&update.path)
        || !current_executable.is_absolute()
        || !is_regular_file(current_executable)
        || !matches_digest(update)
    {
        return Err(NativeUpdateInstallError::InvalidArtifact);
    }
    let kind = UpdateArtifactKind::from_path(&update.path)
        .map_err(|_| NativeUpdateInstallError::InvalidArtifact)?;
    #[cfg(target_os = "linux")]
    return install_linux(kind, &update.path, current_executable);
    #[cfg(target_os = "macos")]
    return install_macos(kind, &update.path, current_executable);
    #[cfg(target_os = "windows")]
    return install_windows(kind, &update.path);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (kind, current_executable);
        Err(NativeUpdateInstallError::UnsupportedPlatform)
    }
}

fn matches_digest(update: &StagedUpdate) -> bool {
    if update.artifact_sha256.len() != 64
        || update.artifact_sha256 != update.artifact_sha256.to_ascii_lowercase()
        || !update
            .artifact_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    let Ok(mut file) = fs::File::open(&update.path) else {
        return false;
    };
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => digest.update(&buffer[..size]),
            Err(_) => return false,
        }
    }
    hex::encode(digest.finalize()) == update.artifact_sha256
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

#[cfg(target_os = "linux")]
fn install_linux(
    kind: UpdateArtifactKind,
    staged: &Path,
    current_executable: &Path,
) -> Result<(), NativeUpdateInstallError> {
    match kind {
        UpdateArtifactKind::AppImage => replace_appimage(staged, current_executable),
        UpdateArtifactKind::Debian => run_command(
            Command::new("pkexec")
                .arg("dpkg")
                .arg("--install")
                .arg(staged),
        ),
        _ => Err(NativeUpdateInstallError::UnsupportedPlatform),
    }
}

#[cfg(target_os = "linux")]
fn replace_appimage(staged: &Path, current: &Path) -> Result<(), NativeUpdateInstallError> {
    if current.extension().and_then(|value| value.to_str()) != Some("AppImage") {
        return Err(NativeUpdateInstallError::InvalidArtifact);
    }
    let parent = current
        .parent()
        .ok_or(NativeUpdateInstallError::InvalidArtifact)?;
    let temporary = parent.join(format!(".runne-update-{}.tmp", std::process::id()));
    if temporary.exists() {
        return Err(NativeUpdateInstallError::InvalidArtifact);
    }
    let result = (|| {
        let mut source =
            fs::File::open(staged).map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
        io::copy(&mut source, &mut target)
            .map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
        target
            .sync_all()
            .map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
        let mut permissions = target
            .metadata()
            .map_err(|_| NativeUpdateInstallError::InstallerFailed)?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&temporary, permissions)
            .map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
        fs::rename(&temporary, current).map_err(|_| NativeUpdateInstallError::InstallerFailed)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(target_os = "macos")]
fn install_macos(
    kind: UpdateArtifactKind,
    staged: &Path,
    current_executable: &Path,
) -> Result<(), NativeUpdateInstallError> {
    if kind != UpdateArtifactKind::MacDmg {
        return Err(NativeUpdateInstallError::UnsupportedPlatform);
    }
    let bundle = current_executable
        .ancestors()
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("app"))
        .ok_or(NativeUpdateInstallError::InvalidArtifact)?;
    let bundle_name = bundle
        .file_name()
        .ok_or(NativeUpdateInstallError::InvalidArtifact)?;
    let parent = bundle
        .parent()
        .ok_or(NativeUpdateInstallError::InvalidArtifact)?;
    let mount = std::env::temp_dir().join(format!("runne-update-mount-{}", std::process::id()));
    let replacement = parent.join(format!(
        ".{}.new-{}",
        bundle_name.to_string_lossy(),
        std::process::id()
    ));
    let backup = parent.join(format!(
        ".{}.old-{}",
        bundle_name.to_string_lossy(),
        std::process::id()
    ));
    if mount.exists() || replacement.exists() || backup.exists() {
        return Err(NativeUpdateInstallError::InvalidArtifact);
    }
    fs::create_dir(&mount).map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
    let result = (|| {
        run_command(
            Command::new("hdiutil")
                .arg("attach")
                .arg("-nobrowse")
                .arg("-readonly")
                .arg("-mountpoint")
                .arg(&mount)
                .arg(staged),
        )?;
        let source = mount.join(bundle_name);
        run_command(Command::new("ditto").arg(&source).arg(&replacement))?;
        fs::rename(bundle, &backup).map_err(|_| NativeUpdateInstallError::InstallerFailed)?;
        if let Err(error) = fs::rename(&replacement, bundle) {
            let _ = fs::rename(&backup, bundle);
            let _ = error;
            return Err(NativeUpdateInstallError::InstallerFailed);
        }
        let _ = fs::remove_dir_all(&backup);
        Ok(())
    })();
    let _ = Command::new("hdiutil").arg("detach").arg(&mount).status();
    let _ = fs::remove_dir(&mount);
    if result.is_err() {
        let _ = fs::remove_dir_all(&replacement);
    }
    result
}

#[cfg(target_os = "windows")]
fn install_windows(
    kind: UpdateArtifactKind,
    staged: &Path,
) -> Result<(), NativeUpdateInstallError> {
    if kind != UpdateArtifactKind::WindowsNsis {
        return Err(NativeUpdateInstallError::UnsupportedPlatform);
    }
    use std::os::windows::process::CommandExt;
    Command::new(staged)
        .args(["/S", "/CLOSEAPPLICATIONS", "/NORESTART"])
        .creation_flags(0x0000_0008 | 0x0000_0200)
        .spawn()
        .map(|_| ())
        .map_err(|_| NativeUpdateInstallError::InstallerFailed)
}

fn run_command(command: &mut Command) -> Result<(), NativeUpdateInstallError> {
    command
        .status()
        .map_err(|_| NativeUpdateInstallError::InstallerFailed)?
        .success()
        .then_some(())
        .ok_or(NativeUpdateInstallError::InstallerFailed)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn appimage_replacement_is_atomic_and_keeps_staged_source() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("Runne.AppImage");
        let staged = directory.path().join("runne-1.2.0-aaaaaaaa.AppImage");
        fs::write(&current, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();
        fs::set_permissions(&current, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
        let update = StagedUpdate {
            path: staged.clone(),
            artifact_sha256: "11507a0e2f5e69d5dfa40a62a1bd7b6ee57e6bcd85c67c9b8431b36fff21c437"
                .into(),
        };
        install_staged_update(&update, &current).unwrap();
        assert_eq!(fs::read(&current).unwrap(), b"new");
        assert_eq!(fs::read(staged).unwrap(), b"new");
    }

    #[test]
    fn appimage_replacement_rejects_non_appimage_installation() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("runne-desktop");
        let staged = directory.path().join("runne-1.2.0-aaaaaaaa.AppImage");
        fs::write(&current, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();
        let update = StagedUpdate {
            path: staged,
            artifact_sha256: "11507a0e2f5e69d5dfa40a62a1bd7b6ee57e6bcd85c67c9b8431b36fff21c437"
                .into(),
        };
        assert_eq!(
            install_staged_update(&update, &current),
            Err(NativeUpdateInstallError::InvalidArtifact)
        );
    }

    #[test]
    fn installer_rejects_a_replaced_staged_artifact_digest() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("Runne.AppImage");
        let staged = directory.path().join("runne-1.2.0-aaaaaaaa.AppImage");
        fs::write(&current, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();
        fs::set_permissions(&current, fs::Permissions::from_mode(0o755)).unwrap();
        let update = StagedUpdate {
            path: staged,
            artifact_sha256: "a".repeat(64),
        };
        assert_eq!(
            install_staged_update(&update, &current),
            Err(NativeUpdateInstallError::InvalidArtifact)
        );
        assert_eq!(fs::read(current).unwrap(), b"old");
    }
}
