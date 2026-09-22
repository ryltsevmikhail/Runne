//! Real first-party writer binary tests: live admission of the actual
//! `runne` binary, deterministic bounded startup-EOF exit, and the pidfd
//! fault-retry that kills the hung real writer before returning.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec, fixture_dir, fixture_socket, unix_daemon,
};
use crate::provider_credential_broker::RetainedWriterProcess as _;

fn real_writer_binary() -> PathBuf {
    let harness = std::env::current_exe().expect("test exe");
    let binary = harness
        .parent()
        .and_then(|deps| deps.parent())
        .map(|debug| debug.join("runne"))
        .expect("target layout");
    assert!(binary.is_file(), "real writer binary required");
    binary
}

fn real_writer_spec() -> VerifiedWriterLaunchSpec {
    use sha2::Digest as _;
    let binary = real_writer_binary();
    let digest: [u8; 32] = sha2::Sha256::digest(&std::fs::read(&binary).unwrap()).into();
    VerifiedWriterLaunchSpec::new(VerifiedWriterArtifact::new(binary, digest, [3; 32]).unwrap())
}

#[test]
fn real_writer_loop_is_alive_until_transport_eof_and_admits() {
    let dir = fixture_dir("reallive");
    let address = fixture_socket(&dir);
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process = unix_daemon::test_spawn_linux_writer(
        &real_writer_spec(),
        child_half,
        handshake_child,
        &address,
    )
    .expect("spawn the REAL writer binary");
    // The writer blocks waiting for its private startup exchange while both
    // halves stay open, so admission measures a live first-party writer.
    let admission = crate::provider_credential_broker::linux_writer_admission::admit_linux_writer(
        &process,
        &real_writer_spec(),
    )
    .expect("real live writer admits with matching facts");
    assert_eq!(admission.pid(), process.retained_pid());
    // Deterministic bounded exit: closing the private startup socket ends
    // the startup exchange (the daemon never answered), then EOF on the
    // broker control stdin finishes the loop.
    drop(handshake_parent);
    drop(parent_half);
    process
        .reap_retained_child()
        .expect("bounded startup-EOF exit reaped");
}

#[test]
fn pidfd_fault_retry_kills_the_hung_real_writer_before_return() {
    let dir = fixture_dir("faultkill");
    let address = fixture_socket(&dir);
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let observed_pid = std::sync::Arc::new(std::sync::Mutex::new(None::<i32>));
    let seen = std::sync::Arc::clone(&observed_pid);
    let injected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let injected_once = std::sync::Arc::clone(&injected);
    let error = unix_daemon::linux_spawn::spawn_with_pidfd_acquisition(
        &real_writer_spec(),
        child_half,
        handshake_child,
        &address,
        move |pid| {
            *seen.lock().unwrap() = Some(pid);
            if !injected_once.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
            }
            let child = rustix::process::Pid::from_raw(pid)
                .ok_or_else(|| std::io::Error::other("invalid pid"))?;
            rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty())
                .map_err(std::io::Error::from)
        },
    )
    .err()
    .expect("explicit unresolved-child failure");
    assert!(matches!(error, BrokerHandoffError::Rejected));
    let pid = observed_pid.lock().unwrap().expect("fault observed pid");
    // The retry path acquired a REAL pidfd, SIGKILLed the exact hung child
    // (transport still open — no EOF rescue), and reaped it before the
    // error surfaced: the pid no longer exists.
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "hung writer must be killed and reaped before returning"
    );
    drop(parent_half);
}
