use super::{capture_linux_peer, verify_linux_enrollment_peer};
use runne_api::provider_credential_enrollment::linux_activation_policy::{
    LinuxInstallationFacts, LinuxInstallationLayout,
};
use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

/// Read-only policy facts for the exact peer in the signed prepare transcript.
/// This is not qualification evidence or writer authority.
#[must_use]
pub fn measure_verified_linux_enrollment_installation(
    stream: &UnixStream,
    claims: &runne_api::VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
    runtime_root: &Path,
    live_authority: [u8; 16],
    expected_daemon_image: [u8; 32],
) -> Option<LinuxInstallationFacts> {
    if runtime_root.canonicalize().ok()?.as_path() != runtime_root {
        return None;
    }
    super::super::validate_owner_private_directory(runtime_root).ok()?;
    let peer = capture_linux_peer(stream)?;
    if !verify_linux_enrollment_peer(stream, claims) {
        return None;
    }
    let desktop = std::path::PathBuf::from(format!("/proc/{}/exe", peer.pid));
    let desktop_package = std::fs::canonicalize(&desktop).ok()?;
    if desktop_package != Path::new(&peer.executable_path) {
        return None;
    }
    let writer = package_writer_for_desktop(&desktop_package)?;
    let facts = LinuxInstallationLayout {
        runtime_root,
        desktop_image: &desktop,
        writer_image: &writer,
        daemon_image: Path::new("/proc/self/exe"),
        machine_id_path: Path::new("/etc/machine-id"),
    }
    .canonicalize_facts(live_authority)?;
    if facts.daemon_image_digest != expected_daemon_image
        || capture_linux_peer(stream)? != peer
        || !verify_linux_enrollment_peer(stream, claims)
    {
        return None;
    }
    Some(facts)
}

fn package_writer_for_desktop(desktop: &Path) -> Option<PathBuf> {
    let desktop = desktop.canonicalize().ok()?;
    let writer = desktop.parent()?.join("runne");
    let metadata = std::fs::symlink_metadata(&writer).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || writer.canonicalize().ok()?.as_path() != writer
    {
        return None;
    }
    Some(writer)
}

#[cfg(test)]
#[path = "installation_tests.rs"]
mod tests;
