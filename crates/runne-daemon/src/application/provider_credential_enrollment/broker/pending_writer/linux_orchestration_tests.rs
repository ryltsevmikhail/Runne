//! B8 stage-4 end-to-end: the PRODUCTION orchestrator launches the REAL
//! first-party writer binary through the real spawn entry (broker control on
//! stdin, private startup socket on stdout), receives the live cross-bound
//! handshake, and returns the consolidated Linux broker channel.

use std::os::unix::net::UnixStream;

use runne_platform_desktop::provider_credential_broker::spawn_linux_writer_with_sockets;
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::application::provider_credential_enrollment::broker::rendezvous::DaemonBrokerAuthority;

fn real_writer_launch_spec() -> VerifiedWriterLaunchSpec {
    let harness = std::env::current_exe().expect("test exe");
    let binary = harness
        .parent()
        .and_then(|deps| deps.parent())
        .map(|debug| debug.join("runne"))
        .expect("target layout");
    assert!(
        binary.is_file(),
        "first-party binary required: {}",
        binary.display()
    );
    let digest: [u8; 32] = Sha256::digest(&std::fs::read(&binary).unwrap()).into();
    VerifiedWriterLaunchSpec::new(VerifiedWriterArtifact::new(binary, digest, [3; 32]).unwrap())
}

fn orchestrator_fixture(
    secret: [u8; 32],
) -> (
    PendingBrokerRendezvousBinding,
    DaemonBrokerAuthority,
    UnixStream,
    runne_api::ProviderCredentialBrokerTransferAuthority,
) {
    let fixture = binding_fixture(4_000_000_000);
    let (transfer, _) = transfer_authority(&fixture.issuer, secret, [4; 32]);
    let channel = [31; 32];
    let (daemon_control, writer_control) = UnixStream::pair().unwrap();
    let authority = DaemonBrokerAuthority::for_test_endpoint(channel, daemon_control);
    let binding = PendingBrokerRendezvousBinding::new(
        &fixture.operation,
        &fixture.authority,
        &fixture.proof,
        100,
    )
    .unwrap();
    (binding, authority, writer_control, transfer)
}

#[test]
fn orchestrator_launches_the_real_writer_into_a_verified_channel() {
    let (binding, authority, writer_control, transfer) = orchestrator_fixture([31; 32]);
    let spec = real_writer_launch_spec();
    let spawned_spec = real_writer_launch_spec();
    let spawn: LinuxWriterSpawn = Box::new(move |control, handshake| {
        spawn_linux_writer_with_sockets(&spawned_spec, control, handshake)
            .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::Unavailable)
    });
    let launch = launch_linux_writer_with_handshake(
        authority,
        writer_control,
        binding,
        transfer,
        &[31; 32],
        [55; 32],
        &spec,
        spawn,
    );
    // The launch itself is the proof: only the handshake-authenticated kill
    // key plus live pidfd admission can produce this channel.
    let channel_state = launch.expect("real writer completes the verified startup");
    channel_state.terminate_exact_writer();
}

#[test]
fn orchestrator_denies_a_wrong_startup_launch_secret() {
    let (binding, authority, writer_control, transfer) = orchestrator_fixture([31; 32]);
    let spec = real_writer_launch_spec();
    let spawned_spec = real_writer_launch_spec();
    let spawn: LinuxWriterSpawn = Box::new(move |control, handshake| {
        spawn_linux_writer_with_sockets(&spawned_spec, control, handshake)
            .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::Unavailable)
    });
    let denied = launch_linux_writer_with_handshake(
        authority,
        writer_control,
        binding,
        transfer,
        &[40; 32],
        [55; 32],
        &spec,
        spawn,
    );
    assert!(
        denied.is_err(),
        "a writer started with the wrong startup secret must never yield a channel"
    );
}
