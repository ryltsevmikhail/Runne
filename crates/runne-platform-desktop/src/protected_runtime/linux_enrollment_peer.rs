// Linux local-runtime enrollment peer verification.
//
// The desktop supervisor and the daemon share one local uid; the daemon
// authenticates the control-channel peer through the kernel credential
// (SO_PEERCRED) and binds the transition to the measured desktop process:
// the executable path and the kernel process start time. The macOS codesign
// and qualification admission have no Linux equivalent and are not simulated;
// every daemon-side signature and reservation check still applies.

use sha2::{Digest, Sha256};
use std::os::unix::net::UnixStream;

const PEER_BINDING_DOMAIN: &[u8] = b"runne/linux-desktop-peer-binding/v1\0";

#[cfg(target_os = "linux")]
struct LinuxPeerIdentity {
    pid: u32,
    uid: u32,
    executable_path: String,
    process_start_ticks: u64,
}

#[cfg(target_os = "linux")]
fn capture_linux_peer(stream: &UnixStream) -> Option<LinuxPeerIdentity> {
    let peer = rustix::net::sockopt::socket_peercred(stream).ok()?;
    let pid = u32::try_from(peer.pid.as_raw_pid()).ok()?;
    if pid == 0 {
        return None;
    }
    let uid = peer.uid.as_raw();
    let executable_path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()?
        .to_string_lossy()
        .into_owned();
    let process_start_ticks = read_process_start_ticks(pid)?;
    Some(LinuxPeerIdentity {
        pid,
        uid,
        executable_path,
        process_start_ticks,
    })
}

#[cfg(target_os = "linux")]
fn own_process_facts() -> Option<(u32, u32, String, u64)> {
    let pid = std::process::id();
    let uid = rustix::process::geteuid().as_raw();
    let executable_path = std::fs::read_link("/proc/self/exe")
        .ok()?
        .to_string_lossy()
        .into_owned();
    let process_start_ticks = read_process_start_ticks(pid)?;
    Some((pid, uid, executable_path, process_start_ticks))
}

#[cfg(target_os = "linux")]
fn read_process_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_command = stat.rsplit_once(')')?.1;
    // Fields restart at `state` (field 3) after the parenthesised command;
    // `starttime` is field 22, i.e. index 19 of the remainder.
    after_command.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)] // The binding tuple stays explicit.
fn peer_binding_digest(
    release_tuple: [u8; 32],
    pid: u32,
    uid: u32,
    executable_path: &str,
    process_start_ticks: u64,
    launch_authority: [u8; 16],
    desktop_host: [u8; 16],
    supervisor_generation: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PEER_BINDING_DOMAIN);
    for value in [
        release_tuple.as_slice(),
        pid.to_le_bytes().as_slice(),
        uid.to_le_bytes().as_slice(),
        supervisor_generation.to_le_bytes().as_slice(),
        process_start_ticks.to_le_bytes().as_slice(),
    ] {
        hasher.update(value);
    }
    hasher.update(executable_path.as_bytes());
    hasher.update(launch_authority);
    hasher.update(desktop_host);
    hasher.finalize().into()
}

/// Daemon side: authenticates the control-channel peer as the same-uid live
/// desktop supervisor whose signed V2 claims name exactly this process.
#[cfg(target_os = "linux")]
#[must_use]
pub fn verify_linux_enrollment_peer(
    stream: &UnixStream,
    claims: &runne_api::VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
) -> bool {
    let Some(peer) = capture_linux_peer(stream) else {
        return false;
    };
    let own_uid = rustix::process::geteuid().as_raw();
    if peer.uid != own_uid || peer.pid == std::process::id() {
        return false;
    }
    let digest = peer_binding_digest(
        *claims.release_tuple_digest(),
        peer.pid,
        peer.uid,
        &peer.executable_path,
        peer.process_start_ticks,
        *claims.launch_authority_id(),
        *claims.desktop_host_instance_id(),
        claims.desktop_supervisor_generation(),
    );
    digest == *claims.desktop_peer_binding_digest()
}

/// Supervisor side: measures this exact process into the peer binding digest
/// the daemon independently recomputes from the live kernel peer.
#[cfg(target_os = "linux")]
#[must_use]
pub fn linux_enrollment_peer_binding(
    release_tuple: [u8; 32],
    launch_authority: [u8; 16],
    desktop_host: [u8; 16],
    supervisor_generation: u64,
) -> Option<[u8; 32]> {
    let (pid, uid, executable_path, process_start_ticks) = own_process_facts()?;
    Some(peer_binding_digest(
        release_tuple,
        pid,
        uid,
        &executable_path,
        process_start_ticks,
        launch_authority,
        desktop_host,
        supervisor_generation,
    ))
}
