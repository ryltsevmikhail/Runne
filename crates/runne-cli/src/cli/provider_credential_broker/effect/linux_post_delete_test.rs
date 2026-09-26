//! Explicit Linux test hook for killing the retained writer after Revoke.

use super::CliError;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::time::{Duration, Instant};

const FIXTURE_ENV: &str = "RUNNE_D1_1B_POST_DELETE_KILL_FIXTURE_ROOT";

pub(super) fn kill_after_delete(result: &Result<(), CliError>) -> Result<(), CliError> {
    if result.is_err() {
        return Ok(());
    }
    let Some(root) = std::env::var_os(FIXTURE_ENV) else {
        return Ok(());
    };
    #[cfg(feature = "linux-native-enrollment-qualification")]
    let root = runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::validate_fixture_root(std::path::Path::new(&root))
        .map_err(|_| CliError::CredentialOperation)?;
    #[cfg(not(feature = "linux-native-enrollment-qualification"))]
    let root = std::fs::canonicalize(root).map_err(|_| CliError::CredentialOperation)?;
    let marker = root.join("post-delete.marker");
    let release = root.join("post-delete.release");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(marker)
        .map_err(|_| CliError::CredentialOperation)?;
    writeln!(file, "{}", std::process::id())
        .and_then(|()| file.sync_all())
        .map_err(|_| CliError::CredentialOperation)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if release.is_file() {
            // This is the exact writer after its native Revoke and before
            // NativeEffectObserved. It must die without sending an ACK.
            nix::sys::signal::raise(nix::sys::signal::Signal::SIGKILL)
                .map_err(|_| CliError::CredentialOperation)?;
            return Err(CliError::CredentialOperation);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(CliError::CredentialOperation)
}
