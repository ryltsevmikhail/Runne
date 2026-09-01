#![cfg(test)]

use crate::MacOsLocalPeerProcessIdentity;
use crate::packaged_writer_observation::security_code::{
    NativeCodeObservation, test_only_guest_from_audit_token,
};
use std::io::{Read as _, Write as _};
use std::os::unix::process::CommandExt as _;

#[test]
fn self_code_has_a_valid_requirement_free_native_main_executable() {
    let code = NativeCodeObservation::capture_self().unwrap();

    assert_eq!(code.main_executable(), std::env::current_exe().unwrap());
    assert!(code.revalidate().is_ok());
}

#[test]
fn peer_code_is_resolved_only_from_the_socket_audit_token() {
    let (local, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let peer = MacOsLocalPeerProcessIdentity::capture(&local).unwrap();
    let code = NativeCodeObservation::capture_peer(&peer).unwrap();

    assert_eq!(code.main_executable(), std::env::current_exe().unwrap());
    assert!(code.revalidate().is_ok());
}

#[test]
fn an_empty_audit_token_cannot_resolve_a_guest_code() {
    let token = nix::sys::socket::audit_token_t::default();

    assert!(test_only_guest_from_audit_token(&token).is_err());
}

#[test]
fn peer_exec_drift_is_rejected_while_the_original_control_socket_remains_open() {
    let path = std::env::temp_dir().join(format!("runne-b2b2ii-peer-exec-{}", std::process::id()));
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "packaged_writer_observation_tests::security_code::peer_exec_helper",
            "--nocapture",
        ])
        .env("RUNNE_B2B2II_PEER_EXEC_SOCKET", &path)
        .spawn()
        .unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let mut ready = [0_u8; 1];
    stream.read_exact(&mut ready).unwrap();
    let peer = MacOsLocalPeerProcessIdentity::capture(&stream).unwrap();
    let code = NativeCodeObservation::capture_peer(&peer).unwrap();

    stream.write_all(&[1]).unwrap();
    let rejected_during_exec = (0..100).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        NativeCodeObservation::capture_peer(&peer)
            .and_then(|fresh| code.matches_fresh(&fresh))
            .is_err()
            && peer.revalidate_same_peer(&stream).is_err()
            && child.try_wait().unwrap().is_none()
    });

    assert!(rejected_during_exec, "live peer exec was not rejected");
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn peer_exec_helper() {
    let Ok(path) = std::env::var("RUNNE_B2B2II_PEER_EXEC_SOCKET") else {
        return;
    };
    let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
    stream.write_all(&[1]).unwrap();
    let mut proceed = [0_u8; 1];
    stream.read_exact(&mut proceed).unwrap();
    nix::fcntl::fcntl(
        &stream,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    let error = std::process::Command::new("/bin/sleep").arg("5").exec();
    panic!("exec failed: {error}");
}
