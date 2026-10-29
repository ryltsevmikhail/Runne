use super::policy::{HostResult, ImagePolicy};
use runne_provider::*;
use sha2::{Digest, Sha256};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(super) fn hash(role: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne/linux-cli-credential-host/v1\0");
    hash.update((role.len() as u64).to_be_bytes());
    hash.update(role);
    hash.update(bytes);
    hash.finalize().into()
}
pub(super) fn binding(role: &[u8], bytes: &[u8]) -> HostResult<CredentialBindingDigest> {
    CredentialBindingDigest::from_measured(hash(role, bytes)).map_err(|_| "invalid host binding")
}
pub(super) fn seal(
    authority: &CredentialEnrollmentMeasurementAuthority,
    policy: &ImagePolicy,
    runtime: [u8; 16],
    installation: CredentialBindingDigest,
    draft: ClaimCredentialOperation,
) -> HostResult<ClaimCredentialOperation> {
    let process = std::fs::read("/proc/self/stat").map_err(|_| "process identity unavailable")?;
    // Retain an actual kernel handle to this process through claim sealing.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if raw < 0 {
        return Err("process handle unavailable");
    }
    let handle = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let handle_info = std::fs::read(format!("/proc/self/fdinfo/{}", handle.as_raw_fd()))
        .map_err(|_| "process handle identity unavailable")?;
    let measurements = (|| {
        CredentialMeasurementSnapshot::new(
            authority.candidate_source_identity(hash(b"owner-session", &policy.manifest))?,
            authority.release_manifest_digest(installation.as_bytes())?,
            authority.desktop_executable_identity(hash(b"cli", &policy.cli_digest))?,
            authority.writer_executable_identity(hash(b"writer", &policy.host_digest))?,
            authority.reader_executable_identity(hash(b"reader", &policy.daemon_digest))?,
            authority.contract_bundle_digest(hash(b"standalone-contract", b"deepseek-pair-v1"))?,
            authority.daemon_authority_id(hash(b"runtime", &runtime))?,
            authority.protected_session_id(hash(b"tty-session", &process))?,
            authority.desktop_supervisor_generation(draft.desktop_supervisor_generation())?,
            authority.writer_launch_id(hash(b"launch", &process))?,
            authority.writer_process_start_identity(hash(b"process-start", &process))?,
            authority.writer_process_handle_identity(hash(b"process-handle", &handle_info))?,
            authority.broker_channel_binding(hash(
                b"in-process-tty",
                &draft.continuation_binding_digest().as_bytes(),
            ))?,
            authority
                .continuation_binding_digest(draft.continuation_binding_digest().as_bytes())?,
        )
    })()
    .map_err(|_| "host measurements rejected")?;
    let digest = authority
        .measure_claim_operation(&measurements, &draft)
        .map_err(|_| "claim measurement rejected")?;
    let bound = draft
        .bind_process_release_digest(digest)
        .map_err(|_| "claim binding rejected")?;
    authority
        .seal_claim_operation(measurements, bound)
        .map_err(|_| "host claim rejected")
}
