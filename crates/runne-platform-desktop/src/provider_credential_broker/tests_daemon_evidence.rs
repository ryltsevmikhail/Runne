use std::io::Write as _;

use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};

use super::daemon_evidence::{
    receive_daemon_owned_writer_evidence, send_daemon_owned_writer_evidence,
};
use super::*;

#[cfg(unix)]
#[test]
fn daemon_owned_evidence_round_trip_has_no_descriptor() {
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([11; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let evidence =
        WriterProcessEvidence::test_only_daemon([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]);
    let receiver_thread = std::thread::spawn(move || {
        receive_daemon_owned_writer_evidence(receiver, &receiver_authenticator, [4; 32], [5; 32])
    });

    send_daemon_owned_writer_evidence(sender, &sender_authenticator, &evidence).unwrap();
    let evidence_received = receiver_thread.join().unwrap().unwrap();
    let launch = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new("/verified/runne".into(), [2; 32], [3; 32]).unwrap(),
    );
    assert!(evidence_received.matches_daemon_owned_launch(&launch, [4; 32], [5; 32]));
}

#[cfg(unix)]
#[test]
fn daemon_owned_evidence_rejects_a_channel_or_key_substitution() {
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([12; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let evidence =
        WriterProcessEvidence::test_only_daemon([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]);
    let receiver_thread = std::thread::spawn(move || {
        receive_daemon_owned_writer_evidence(receiver, &receiver_authenticator, [4; 32], [6; 32])
    });

    assert_eq!(
        send_daemon_owned_writer_evidence(sender, &sender_authenticator, &evidence),
        Err(BrokerHandoffError::Rejected)
    );
    assert!(matches!(
        receiver_thread.join().unwrap(),
        Err(BrokerHandoffError::Rejected)
    ));
}

#[cfg(unix)]
#[test]
fn daemon_owned_evidence_rejects_substituted_signed_measurements() {
    for offset in [128, 160, 192] {
        let (mut sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        let keys = LaunchSecret::from_bytes([14; 32]).unwrap().derive_keys();
        let sender_authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let receiver_authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let receiver_thread = std::thread::spawn(move || {
            receive_daemon_owned_writer_evidence(
                receiver,
                &receiver_authenticator,
                [4; 32],
                [5; 32],
            )
        });
        let mut challenge = [0; 128];
        std::io::Read::read_exact(&mut sender, &mut challenge).unwrap();
        let mut response = [0; 256];
        response[..128].copy_from_slice(&challenge);
        response[128..160].copy_from_slice(&[1; 32]);
        response[160..192].copy_from_slice(&[2; 32]);
        response[192..224].copy_from_slice(&[3; 32]);
        let proof = response_proof(&sender_authenticator, &response[..224]);
        response[224..].copy_from_slice(&proof);
        response[offset] ^= 1;
        sender.write_all(&response).unwrap();

        assert!(matches!(
            receiver_thread.join().unwrap(),
            Err(BrokerHandoffError::Rejected)
        ));
    }
}

#[cfg(unix)]
#[test]
fn daemon_owned_evidence_rejects_trailing_bytes() {
    let (mut sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([13; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_thread = std::thread::spawn(move || {
        receive_daemon_owned_writer_evidence(receiver, &receiver_authenticator, [4; 32], [5; 32])
    });
    let mut challenge = [0; 128];
    std::io::Read::read_exact(&mut sender, &mut challenge).unwrap();
    let mut response = [0; 256];
    response[..128].copy_from_slice(&challenge);
    response[128..160].copy_from_slice(&[1; 32]);
    response[160..192].copy_from_slice(&[2; 32]);
    response[192..224].copy_from_slice(&[3; 32]);
    let proof = response_proof(&sender_authenticator, &response[..224]);
    response[224..256].copy_from_slice(&proof);
    let mut framed = response.to_vec();
    framed.push(b'x');
    sender.write_all(&framed).unwrap();

    assert!(matches!(
        receiver_thread.join().unwrap(),
        Err(BrokerHandoffError::Rejected)
    ));
}

#[cfg(unix)]
#[test]
fn daemon_owned_evidence_rejects_a_delayed_trailing_byte_before_acceptance() {
    use std::net::Shutdown;
    use std::time::Duration;

    let (mut sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([15; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_thread = std::thread::spawn(move || {
        let mut challenge = [0; 128];
        std::io::Read::read_exact(&mut sender, &mut challenge).unwrap();
        let mut response = [0; 256];
        response[..128].copy_from_slice(&challenge);
        response[128..160].copy_from_slice(&[1; 32]);
        response[160..192].copy_from_slice(&[2; 32]);
        response[192..224].copy_from_slice(&[3; 32]);
        let proof = response_proof(&sender_authenticator, &response[..224]);
        response[224..].copy_from_slice(&proof);
        sender.write_all(&response).unwrap();
        std::thread::sleep(Duration::from_millis(25));
        let _ = sender.write_all(b"x");
        let _ = sender.shutdown(Shutdown::Write);
    });

    assert!(matches!(
        receive_daemon_owned_writer_evidence(receiver, &receiver_authenticator, [4; 32], [5; 32]),
        Err(BrokerHandoffError::Rejected)
    ));
    sender_thread.join().unwrap();
}

fn response_proof(
    authenticator: &CredentialBrokerTransferAuthenticator,
    record: &[u8],
) -> [u8; 32] {
    let mut transcript =
        b"gocode/provider-credential-broker/daemon-evidence/v1/response\0".to_vec();
    transcript.extend_from_slice(record);
    authenticator.authenticate_transfer(&transcript)
}
