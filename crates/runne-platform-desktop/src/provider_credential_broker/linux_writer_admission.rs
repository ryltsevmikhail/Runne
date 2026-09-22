//! Linux writer admission (M5): binds one spawned writer process to its
//! pinned image digest and retained start identity before the daemon grants
//! any broker authority.
//!
//! Admission combines three process facts, mirroring the macOS live
//! verification minus `SecCode`: (1) the retained `pid` must still execute
//! exactly the pinned image (`/proc/<pid>/exe` canonical path equals the
//! spec executable and the on-disk bytes hash to the signed
//! `VerifiedWriterArtifact::image_digest`), (2) the fresh `/proc` start
//! identity must equal the identity retained at spawn (PID-reuse and
//! drift both deny), and (3) the process stays owned through its retained
//! pidfd, so admission never mints authority for an unowned process.
//! Ticket one-use/TTL/replay and kill ownership live in the existing daemon
//! admission registry and are not re-implemented here.

use std::path::Path;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};
use sha2::{Digest as _, Sha256};

use super::unix::UnixRetainedWriterProcess;
use super::unix::process_start_identity::observed_start_identity;

/// One admitted Linux writer bound to its measured process facts.
pub struct VerifiedLinuxWriterAdmission {
    image_digest: [u8; 32],
    start_identity: [u8; 32],
    pid: libc::pid_t,
}

impl VerifiedLinuxWriterAdmission {
    #[must_use]
    pub const fn image_digest(&self) -> [u8; 32] {
        self.image_digest
    }

    #[must_use]
    pub const fn start_identity(&self) -> [u8; 32] {
        self.start_identity
    }

    #[must_use]
    pub const fn pid(&self) -> libc::pid_t {
        self.pid
    }
}

/// Admits one retained writer against its pinned launch spec.
///
/// # Errors
///
/// Returns a closed failure when the live process no longer matches the
/// pinned image, the start identity drifted, or any fact is unreadable.
pub fn admit_linux_writer(
    process: &UnixRetainedWriterProcess,
    spec: &VerifiedWriterLaunchSpec,
) -> Result<VerifiedLinuxWriterAdmission, BrokerHandoffError> {
    let artifact = spec.artifact();
    let executable = artifact.executable();
    let pinned_digest = artifact.image_digest();
    let pid = process.retained_pid();
    let live_identity = observed_start_identity(pid.unsigned_abs())?;
    if live_identity != process.retained_start_identity() {
        return Err(BrokerHandoffError::Rejected);
    }
    if !executes_pinned_image(pid, executable)? {
        return Err(BrokerHandoffError::Rejected);
    }
    let measured = file_digest(executable)?;
    if measured != pinned_digest {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok(VerifiedLinuxWriterAdmission {
        image_digest: pinned_digest,
        start_identity: live_identity,
        pid,
    })
}

/// The retained process must still execute the exact pinned image path.
fn executes_pinned_image(pid: libc::pid_t, executable: &Path) -> Result<bool, BrokerHandoffError> {
    let live =
        std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|_| BrokerHandoffError::Rejected)?;
    let pinned = executable
        .canonicalize()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    Ok(live == pinned)
}

fn file_digest(path: &Path) -> Result<[u8; 32], BrokerHandoffError> {
    let bytes = std::fs::read(path).map_err(|_| BrokerHandoffError::Rejected)?;
    Ok(Sha256::digest(&bytes).into())
}
