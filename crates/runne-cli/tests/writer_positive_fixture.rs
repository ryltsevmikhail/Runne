//! Positive/denial e2e through the explicitly TEST-ONLY fixture writer
//! example (same production trust path; FAKE in-memory provider store via
//! the established test-support seam — never a real Secret Service).

use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use runne_api::ProviderCredentialRequestAuthorityPair;
use runne_platform_desktop::provider_credential_broker::receive_linux_writer_startup as daemon_receive;
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
use sha2::Digest as _;

#[path = "writer_fixture_support/mod.rs"]
mod support;
use support::*;

fn spawn_writer_with_control(handshake: UnixStream, control: UnixStream) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_runne"))
        .arg(runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(control)))
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(handshake)))
        .stderr(Stdio::null())
        .spawn()
        .expect("writer binary")
}

fn oracle_start_of(pid: u32) -> [u8; 32] {
    oracle_start_identity(pid)
}

fn oracle_image_digest() -> [u8; 32] {
    sha2::Sha256::digest(&std::fs::read(env!("CARGO_BIN_EXE_runne")).unwrap()).into()
}

#[test]
fn real_writer_denies_a_wrong_retained_release_tuple() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = fixture_authority(&issuer);
    let (mut daemon_control, writer_control) = UnixStream::pair().unwrap();
    let (daemon_handshake, writer_handshake) = UnixStream::pair().unwrap();
    let mut child = spawn_writer_with_control(writer_handshake, writer_control);
    let live_start = oracle_start_of(child.id());
    let live_image = oracle_image_digest();
    let receiver = std::thread::spawn(move || {
        let signer = CredentialWriterSessionAttestationSigner::generate(SIGN_CHANNEL).unwrap();
        let kill = daemon_receive(
            daemon_handshake,
            authority,
            &LAUNCH_SECRET,
            RELEASE_TUPLE,
            CHANNEL,
            signer.public_key(),
            live_start,
            live_image,
        )
        .expect("startup handshake");
        let (attestation, frame) =
            sign_control_attestation_with_tuple(signer, live_start, live_image, [77; 32]);
        daemon_control.write_all(&attestation).unwrap();
        daemon_control.write_all(&frame).unwrap();
        kill
    });
    let _kill = receiver.join().unwrap();
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "a signed tuple that mismatches the INDEPENDENT startup payload tuple must deny"
    );
}

#[test]
fn fixture_writer_authenticates_and_constructs_writers_with_fake_store() {
    fixture_writer_entry(true, None);
}

#[test]
fn fixture_writer_accepts_ordinary_linux_daemon_attestation() {
    fixture_writer_entry(false, None);
}

#[test]
fn signed_wrong_reader_start_or_image_is_denied_for_both_versions() {
    for qualified in [false, true] {
        for fault in [ReaderFault::Start, ReaderFault::Image] {
            fixture_writer_entry(qualified, Some(fault));
        }
    }
}

fn fixture_writer_entry(qualified: bool, fault: Option<ReaderFault>) {
    // Build the explicitly test-only fixture writer (same trust path, FAKE
    // in-memory provider store via the established test-support seam).
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "-p",
            "runne-cli",
            "--example",
            "writer_fixture",
        ])
        .output()
        .expect("cargo build example");
    assert!(out.status.success(), "example build failed");
    // Cargo supplies the production binary in the active target/profile,
    // including when CARGO_TARGET_DIR is set by the caller.
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_runne"))
        .parent()
        .expect("binary target directory")
        .join("examples/writer_fixture");
    assert!(binary.is_file(), "fixture writer binary missing");

    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = fixture_authority(&issuer);
    let (mut daemon_control, writer_control) = UnixStream::pair().unwrap();
    let (daemon_handshake, writer_handshake) = UnixStream::pair().unwrap();
    let mut child = std::process::Command::new(&binary)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(writer_control)))
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer_handshake)))
        .stderr(Stdio::null())
        .spawn()
        .expect("fixture writer");
    let live_start = oracle_start_of(child.id());
    let live_image: [u8; 32] = sha2::Sha256::digest(&std::fs::read(&binary).unwrap()).into();
    let receiver = std::thread::spawn(move || {
        let signer = CredentialWriterSessionAttestationSigner::generate(SIGN_CHANNEL).unwrap();
        let kill = daemon_receive(
            daemon_handshake,
            authority,
            &LAUNCH_SECRET,
            RELEASE_TUPLE,
            CHANNEL,
            signer.public_key(),
            live_start,
            live_image,
        )
        .expect("startup handshake");
        let (attestation, frame) = sign_attestation_for_reader(
            signer, live_start, live_image, SIGN_TUPLE, qualified, fault,
        );
        let mut coalesced = attestation;
        coalesced.extend_from_slice(&frame);
        coalesced.extend_from_slice(if qualified { b"fixture2" } else { b"fixture1" });
        daemon_control.write_all(&coalesced).unwrap();
        kill
    });
    let _kill = receiver.join().unwrap();
    // This fixture ends after authenticated entry and writer construction.
    // It drops the ticket and effect route without claiming or using them.
    // Success here is not qualified-claim, store-effect, or native evidence.
    let status = child.wait().unwrap();
    assert_eq!(
        status.success(),
        fault.is_none(),
        "only a signed reader matching the kernel control peer may authenticate"
    );
}
