//! Broker handoff mounted in the V3 control loop: shared fixtures.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchAuthorityError,
    ProtectedCredentialEnrollmentShutdownAckV3, ProtectedCredentialEnrollmentShutdownV3,
    ProviderCredentialBrokerHandoffContext, ProviderCredentialBrokerHandoffFrame,
    ProviderCredentialBrokerKillBindingV1, ProviderCredentialBrokerKillRelinquishedProof,
};
use runne_platform_desktop::provider_credential_broker::send_daemon_control_transport_half;

use super::ProtectedActivationChannel;
use super::control_v3::run_control_loop_v3;
use super::enrollment_control_transition::DaemonEnrollmentRendezvous;
pub(crate) use super::enrollment_v3_tests::{owned_and_sessions, read_frame};

pub(crate) const NOW: u64 = 1_000;

pub(crate) struct BrokerFixture {
    pub context: ProviderCredentialBrokerHandoffContext,
    pub binding: [u8; 32],
    pub publication_public_key: [u8; 32],
    pub desktop: CredentialBrokerTransferAuthenticator,
    pub client: UnixStream,
    pub server: std::thread::JoinHandle<Result<(), LaunchAuthorityError>>,
}

pub(crate) fn broker_fixture() -> BrokerFixture {
    let (owned, keys, sessions) = owned_and_sessions();
    let rendezvous = DaemonEnrollmentRendezvous::for_test();
    let binding = rendezvous.channel_binding().unwrap();
    let publication_public_key = rendezvous.publication_public_key().unwrap();
    let desktop = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let context = ProviderCredentialBrokerHandoffContext::new(
        *owned.stable().authority_id(),
        *owned.session_id(),
        owned.launch_generation(),
        binding,
    )
    .unwrap();
    let (client, server) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        run_control_loop_v3(
            ProtectedActivationChannel::new(server).unwrap(),
            keys,
            owned,
            sessions,
            Arc::new(|| Duration::from_secs(1)),
            Arc::new(|| Ok(NOW)),
            rendezvous,
        )
    });
    BrokerFixture {
        context,
        binding,
        publication_public_key,
        desktop,
        client,
        server,
    }
}

pub(crate) fn write_offer(
    fixture: &mut BrokerFixture,
    purpose: u8,
    nonce: [u8; 16],
    issued: u64,
    expires: u64,
) {
    let offer = ProviderCredentialBrokerHandoffFrame::offer(
        fixture.context.clone(),
        purpose,
        issued,
        expires,
        nonce,
        &fixture.desktop,
    )
    .unwrap();
    fixture.client.write_all(&offer.encode_frame()).unwrap();
    let ready = read_frame(&mut fixture.client);
    ProviderCredentialBrokerHandoffFrame::decode_and_verify(
        &ready,
        &fixture.desktop,
        &fixture.context,
        ProviderCredentialBrokerHandoffFrame::PHASE_READY,
        purpose,
        nonce,
        NOW,
    )
    .unwrap();
}

/// Writes one offer without expecting a ready; for rejection paths only.
pub(crate) fn write_offer_without_ready(
    fixture: &mut BrokerFixture,
    purpose: u8,
    nonce: [u8; 16],
    issued: u64,
    expires: u64,
) {
    let offer = ProviderCredentialBrokerHandoffFrame::offer(
        fixture.context.clone(),
        purpose,
        issued,
        expires,
        nonce,
        &fixture.desktop,
    )
    .unwrap();
    fixture.client.write_all(&offer.encode_frame()).unwrap();
}

pub(crate) fn offer_transport_half(
    fixture: &mut BrokerFixture,
    purpose: u8,
    nonce: [u8; 16],
) -> UnixStream {
    write_offer(fixture, purpose, nonce, NOW - 500, NOW + 25_000);
    let (desktop_half, daemon_half) = UnixStream::pair().unwrap();
    send_daemon_control_transport_half(
        &mut fixture.client,
        &daemon_half,
        &fixture.desktop,
        fixture.binding,
    )
    .unwrap();
    desktop_half
}

pub(crate) fn writer_kill_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(crate) fn relinquished_wire(
    binding: ProviderCredentialBrokerKillBindingV1,
    signing_key: &SigningKey,
) -> [u8; 256] {
    let transcript = binding.relinquishment_transcript();
    let proof = ProviderCredentialBrokerKillRelinquishedProof::from_writer_signature(
        binding,
        signing_key.sign(&transcript).to_bytes(),
    );
    proof.to_exact_wire()
}

pub(crate) fn read_to_end(stream: &mut UnixStream) -> Vec<u8> {
    let mut received = Vec::new();
    stream.read_to_end(&mut received).unwrap();
    received
}

#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "only the macOS happy path shuts down gracefully")
)]
pub(crate) fn graceful_shutdown(mut fixture: BrokerFixture) {
    let (owned, keys, _) = owned_and_sessions();
    let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(owned.clone());
    shutdown.sign(&keys);
    fixture
        .client
        .write_all(&shutdown.encode_frame().unwrap())
        .unwrap();
    let acknowledgement =
        ProtectedCredentialEnrollmentShutdownAckV3::decode_frame(&read_frame(&mut fixture.client))
            .unwrap();
    acknowledgement.verify_exact(&owned, &keys).unwrap();
    assert!(fixture.server.join().unwrap().is_ok());
}
