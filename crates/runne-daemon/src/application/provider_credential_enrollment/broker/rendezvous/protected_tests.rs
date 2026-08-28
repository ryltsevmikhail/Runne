use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::path::PathBuf;

use runne_api::LaunchSecret;
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};

use super::*;

#[cfg(target_os = "linux")]
#[test]
fn protected_handoff_moves_only_the_daemon_created_writer_endpoint() {
    let mut rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let expected = rendezvous.channel_binding();
    let expected_publication_key = rendezvous.publication_public_key();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_thread = std::thread::spawn(move || {
        runne_platform_desktop::provider_credential_broker::receive_daemon_owned_writer_endpoint(
            receiver,
            &receiver_authenticator,
            expected,
            expected_publication_key,
        )
    });

    assert_eq!(
        rendezvous
            .handoff_writer_endpoint(sender, &sender_authenticator)
            .unwrap(),
        expected
    );
    let endpoint = receiver_thread.join().unwrap().unwrap();
    assert_eq!(endpoint.channel_binding(), expected);
    assert_eq!(endpoint.publication_public_key(), expected_publication_key);
    let (reused_transport, _) = UnixStream::pair().unwrap();
    assert!(matches!(
        rendezvous.handoff_writer_endpoint(reused_transport, &sender_authenticator),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
}

#[test]
fn daemon_authority_rejects_evidence_with_a_mismatched_writer_measurement() {
    for (image, release) in [([8; 32], [2; 32]), ([1; 32], [9; 32])] {
        let authority = DaemonBrokerAuthority::for_test([4; 32]);
        let evidence = daemon_evidence(
            authority.channel_binding,
            authority.publication_public_key(),
            image,
            release,
        );
        let launch = verified_launch([1; 32], [2; 32]);

        assert!(matches!(
            authority.into_authenticated_channel(evidence, &launch),
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        ));
    }
}

fn daemon_evidence(
    binding: [u8; 32],
    public_key: [u8; 32],
    image: [u8; 32],
    release: [u8; 32],
) -> runne_platform_desktop::provider_credential_broker::WriterProcessEvidence {
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_thread = std::thread::spawn(move || {
        let mut challenge = [0; 128];
        sender.read_exact(&mut challenge).unwrap();
        let mut end = Vec::new();
        sender.read_to_end(&mut end).unwrap();
        assert!(end.is_empty());
        let mut response = [0; 256];
        response[..128].copy_from_slice(&challenge);
        response[128..160].copy_from_slice(&[1; 32]);
        response[160..192].copy_from_slice(&image);
        response[192..224].copy_from_slice(&release);
        let proof = evidence_response_proof(&sender_authenticator, &response[..224]);
        response[224..].copy_from_slice(&proof);
        sender.write_all(&response).unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
    });
    let evidence =
        runne_platform_desktop::provider_credential_broker::receive_daemon_owned_writer_evidence(
            receiver,
            &receiver_authenticator,
            binding,
            public_key,
        )
        .unwrap();
    sender_thread.join().unwrap();
    evidence
}

fn evidence_response_proof(
    authenticator: &CredentialBrokerTransferAuthenticator,
    record: &[u8],
) -> [u8; 32] {
    let mut transcript =
        b"gocode/provider-credential-broker/daemon-evidence/v1/response\0".to_vec();
    transcript.extend_from_slice(record);
    authenticator.authenticate_transfer(&transcript)
}

fn verified_launch(image: [u8; 32], release: [u8; 32]) -> VerifiedWriterLaunchSpec {
    VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(PathBuf::from("/verified/runne"), image, release).unwrap(),
    )
}
