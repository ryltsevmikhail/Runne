//! B8 stage-1 fixture flows: the REAL daemon-evidence protocol over a real
//! socketpair, with peer threads sending valid and invalid evidence frames.

use std::os::unix::net::UnixStream;

use super::*;

const LIVE_START: [u8; 32] = [11; 32];
const LIVE_IMAGE: [u8; 32] = [12; 32];
const KILL_KEY: [u8; 32] = [32; 32];

struct HandshakeFixture {
    transfer: runne_api::ProviderCredentialBrokerTransferAuthority,
    sender: CredentialBrokerTransferAuthenticator,
    launch_secret: [u8; 32],
    issuer: ProviderCredentialRequestAuthorityIssuer,
    channel: [u8; 32],
    publication: [u8; 32],
    release_tuple: [u8; 32],
}

fn handshake_fixture() -> HandshakeFixture {
    let fixture = binding_fixture(4_000_000_000);
    let (transfer, sender) = transfer_authority(&fixture.issuer, [30; 32], [4; 32]);
    let channel = [31; 32];
    let authority = DaemonBrokerAuthority::for_test(channel);
    let publication = authority.publication_public_key();
    HandshakeFixture {
        transfer,
        sender,
        launch_secret: [30; 32],
        issuer: fixture.issuer,
        channel,
        publication,
        release_tuple: fixture.release_tuple,
    }
}

fn exchange(
    fixture: HandshakeFixture,
    kill: [u8; 32],
    live_start: [u8; 32],
    live_image: [u8; 32],
) -> Result<[u8; 32], runne_api::ProviderCredentialEnrollmentHostError> {
    let HandshakeFixture {
        transfer,
        sender,
        issuer: _,
        launch_secret: _,
        channel,
        publication,
        release_tuple,
    } = fixture;
    let frame = [
        LIVE_START,
        LIVE_IMAGE,
        release_tuple,
        channel,
        publication,
        kill,
    ];
    let (sender_end, receiver_end) = UnixStream::pair().unwrap();
    let peer = std::thread::spawn(move || {
        send_test_daemon_owned_writer_evidence(sender_end, &sender, frame)
    });
    let received = receive_linux_writer_evidence(
        receiver_end,
        transfer,
        release_tuple,
        channel,
        publication,
        live_start,
        live_image,
    );
    let _ = peer.join().unwrap();
    received
}

#[test]
fn verified_handshake_delivers_the_authenticated_kill_public_key() {
    let kill = exchange(handshake_fixture(), KILL_KEY, LIVE_START, LIVE_IMAGE).unwrap();
    assert_eq!(kill, KILL_KEY);
}

#[test]
fn evidence_with_mismatched_live_start_is_denied() {
    assert!(
        exchange(handshake_fixture(), KILL_KEY, [77; 32], LIVE_IMAGE).is_err(),
        "frame start must equal the daemon's live pidfd remeasure"
    );
}

#[test]
fn evidence_with_mismatched_live_image_is_denied() {
    assert!(
        exchange(handshake_fixture(), KILL_KEY, LIVE_START, [78; 32]).is_err(),
        "frame image must equal the daemon's live remeasure"
    );
}

#[test]
fn zero_kill_publication_key_is_denied() {
    assert!(
        exchange(handshake_fixture(), [0; 32], LIVE_START, LIVE_IMAGE).is_err(),
        "a zero kill key must never be accepted"
    );
}

#[test]
fn evidence_from_a_foreign_transfer_authority_is_denied() {
    let fixture = handshake_fixture();
    let (_foreign_session, foreign_sender) = transfer_authority(&fixture.issuer, [34; 32], [4; 32]);
    let (sender_end, receiver_end) = UnixStream::pair().unwrap();
    let frame = [
        LIVE_START,
        LIVE_IMAGE,
        fixture.release_tuple,
        fixture.channel,
        fixture.publication,
        KILL_KEY,
    ];
    let peer = std::thread::spawn(move || {
        send_test_daemon_owned_writer_evidence(sender_end, &foreign_sender, frame)
    });
    let received = receive_linux_writer_evidence(
        receiver_end,
        fixture.transfer,
        fixture.release_tuple,
        fixture.channel,
        fixture.publication,
        LIVE_START,
        LIVE_IMAGE,
    );
    assert!(peer.join().unwrap().is_err());
    assert!(
        received.is_err(),
        "a foreign session authenticator must be denied"
    );
}

#[test]
fn real_writer_startup_answers_the_daemon_challenge_cross_bound() {
    use runne_platform_desktop::provider_credential_broker::LinuxWriterLiveFacts;
    use runne_platform_desktop::provider_credential_broker::linux_writer_self_measurements;
    use runne_platform_desktop::provider_credential_broker::receive_linux_writer_startup;
    use runne_platform_desktop::provider_credential_broker::respond_linux_writer_startup;

    let fixture = handshake_fixture();
    let (writer_end, receiver_end) = UnixStream::pair().unwrap();
    let writer = std::thread::spawn(move || respond_linux_writer_startup(writer_end));
    let (live_start, live_image) = linux_writer_self_measurements().unwrap();
    let kill = receive_linux_writer_startup(
        receiver_end,
        fixture.transfer,
        &fixture.launch_secret,
        fixture.release_tuple,
        fixture.channel,
        fixture.publication,
        LinuxWriterLiveFacts {
            start_identity: live_start,
            image_digest: live_image,
        },
    )
    .unwrap();
    let startup = writer.join().unwrap().unwrap();
    assert_eq!(kill, startup.kill_public_key);
    assert_eq!(kill, startup.kill_signing_key.verifying_key().to_bytes());
}

#[test]
fn writer_delivered_a_foreign_launch_secret_is_denied() {
    use runne_platform_desktop::provider_credential_broker::LinuxWriterLiveFacts;
    use runne_platform_desktop::provider_credential_broker::receive_linux_writer_startup;
    use runne_platform_desktop::provider_credential_broker::respond_linux_writer_startup;

    let fixture = handshake_fixture();
    let (writer_end, receiver_end) = UnixStream::pair().unwrap();
    let writer = std::thread::spawn(move || respond_linux_writer_startup(writer_end));
    let received = receive_linux_writer_startup(
        receiver_end,
        fixture.transfer,
        &[40; 32],
        fixture.release_tuple,
        fixture.channel,
        fixture.publication,
        LinuxWriterLiveFacts {
            start_identity: LIVE_START,
            image_digest: LIVE_IMAGE,
        },
    );
    assert!(writer.join().unwrap().is_err());
    assert!(received.is_err(), "a foreign launch secret must be denied");
}

#[test]
fn silent_eof_writer_is_denied() {
    use runne_platform_desktop::provider_credential_broker::LinuxWriterLiveFacts;
    use runne_platform_desktop::provider_credential_broker::receive_linux_writer_startup;

    let fixture = handshake_fixture();
    let (writer_end, receiver_end) = UnixStream::pair().unwrap();
    drop(writer_end);
    assert!(
        receive_linux_writer_startup(
            receiver_end,
            fixture.transfer,
            &fixture.launch_secret,
            fixture.release_tuple,
            fixture.channel,
            fixture.publication,
            LinuxWriterLiveFacts {
                start_identity: LIVE_START,
                image_digest: LIVE_IMAGE,
            },
        )
        .is_err(),
        "a writer that vanishes before answering must be denied"
    );
}
