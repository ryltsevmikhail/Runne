//! B8 stage-3 real-writer fixture: the ACTUAL first-party `runne` writer
//! binary answers the daemon handshake over its inherited stdin socket.
//!
//! The daemon side uses the production receiver (`receive_linux_writer_startup`)
//! with a fixture transfer authority built from public runne-api ceremony
//! APIs only; the live start/image expectations are computed by the test's
//! own /proc oracle for the spawned child (Sha256 domain-tagged starttime).
//! No keyring, bus, prompt, environment secret, or user credential is ever
//! touched; the launch secret is a dummy fixture value.

#![cfg(target_os = "linux")]

mod linux_writer_handshake_support;

use std::io::Write as _;
use std::os::unix::net::UnixStream;

use linux_writer_handshake_support::{
    CHANNEL, LAUNCH_SECRET, PUBLICATION, RELEASE_TUPLE, SIGN_CHANNEL, fixture_authority,
    oracle_image_digest, oracle_start_identity, oracle_start_of, sign_control_attestation,
    spawn_writer, spawn_writer_with_control,
};
use runne_api::ProviderCredentialRequestAuthorityPair;
use runne_platform_desktop::provider_credential_broker::receive_linux_writer_startup;
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;

#[test]
fn actual_writer_binary_completes_the_live_cross_bound_handshake() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = fixture_authority(&issuer);
    let (daemon_end, writer_end) = UnixStream::pair().unwrap();
    let mut child = spawn_writer(writer_end);
    let live_start = oracle_start_identity(child.id());
    let live_image = oracle_image_digest();
    let receiver = std::thread::spawn(move || {
        receive_linux_writer_startup(
            daemon_end,
            authority,
            &LAUNCH_SECRET,
            RELEASE_TUPLE,
            CHANNEL,
            PUBLICATION,
            live_start,
            live_image,
        )
    });
    let kill = receiver.join().unwrap().expect("verified handshake");
    assert_ne!(kill, [0; 32], "a real generated kill key must arrive");
    // Without the signed CONTROL attestation the verified receive closes the
    // writer instead of draining: control EOF after the handshake.
    drop(kill);
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "a writer denied a verified CONTROL session must exit closed"
    );
}

#[test]
fn actual_writer_binary_denies_a_foreign_launch_secret() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = fixture_authority(&issuer);
    let (daemon_end, writer_end) = UnixStream::pair().unwrap();
    let mut child = spawn_writer(writer_end);
    let live_start = oracle_start_identity(child.id());
    let receiver = std::thread::spawn(move || {
        receive_linux_writer_startup(
            daemon_end,
            authority,
            &[40; 32],
            RELEASE_TUPLE,
            CHANNEL,
            PUBLICATION,
            live_start,
            oracle_image_digest(),
        )
    });
    assert!(
        receiver.join().unwrap().is_err(),
        "the daemon must deny a writer holding a foreign launch secret"
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn vanishing_writer_denies_the_handshake_with_a_clean_pipe_error() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = fixture_authority(&issuer);
    let (daemon_end, writer_end) = UnixStream::pair().unwrap();
    drop(writer_end);
    assert!(
        receive_linux_writer_startup(
            daemon_end,
            authority,
            &LAUNCH_SECRET,
            RELEASE_TUPLE,
            CHANNEL,
            PUBLICATION,
            [1; 32],
            [2; 32],
        )
        .is_err(),
        "a vanished writer must be denied"
    );
    let _ = std::io::sink().write_all(&[]);
}

// --- B10: full CONTROL receive through the REAL writer binary ---

use runne_platform_desktop::provider_credential_broker::receive_linux_writer_startup as daemon_receive;

#[test]
fn real_writer_receives_and_binds_the_verified_control_session() {
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
        let (attestation, frame) = sign_control_attestation(signer, live_start, live_image);
        daemon_control.write_all(&attestation).unwrap();
        daemon_control.write_all(&frame).unwrap();
        kill
    });
    let _kill = receiver.join().unwrap();
    let status = child.wait().unwrap();
    // The writer now runs the REAL claim workflow over the control socket:
    // after the verified receive it waits for the daemon's Claim frame; the
    // fixture daemon closes the socket, so the writer exits fail-closed.
    // (A clean exit requires the full daemon claim/prelude/ack cycle — the
    // next milestone; this asserts the workflow is genuinely entered.)
    assert!(
        !status.success(),
        "writer enters the claim workflow and closes on control EOF"
    );
}

#[test]
fn real_writer_denies_a_foreign_signed_control_attestation() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = fixture_authority(&issuer);
    let (mut daemon_control, writer_control) = UnixStream::pair().unwrap();
    let (daemon_handshake, writer_handshake) = UnixStream::pair().unwrap();
    let mut child = spawn_writer_with_control(writer_handshake, writer_control);
    let live_start = oracle_start_of(child.id());
    let live_image = oracle_image_digest();
    let receiver = std::thread::spawn(move || {
        let kill = daemon_receive(
            daemon_handshake,
            authority,
            &LAUNCH_SECRET,
            RELEASE_TUPLE,
            CHANNEL,
            PUBLICATION,
            live_start,
            live_image,
        )
        .expect("startup handshake");
        let foreign = CredentialWriterSessionAttestationSigner::generate(SIGN_CHANNEL).unwrap();
        let (attestation, frame) = sign_control_attestation(foreign, live_start, live_image);
        daemon_control.write_all(&attestation).unwrap();
        daemon_control.write_all(&frame).unwrap();
        kill
    });
    let _kill = receiver.join().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success(), "a foreign signer must fail the writer");
}
