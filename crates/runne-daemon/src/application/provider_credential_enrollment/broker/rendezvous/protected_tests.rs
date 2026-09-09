#[cfg(target_os = "linux")]
use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchSecret, ProviderCredentialBrokerTransferAuthority,
};

#[cfg(target_os = "linux")]
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
    let sender_authority = ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(
        sender_authenticator.clone(),
    );
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

    let _handoff = rendezvous
        .handoff_writer_endpoint(sender, &sender_authority)
        .unwrap();
    let endpoint = receiver_thread.join().unwrap().unwrap();
    assert_eq!(endpoint.channel_binding(), expected);
    assert_eq!(endpoint.publication_public_key(), expected_publication_key);
    let (reused_transport, _) = UnixStream::pair().unwrap();
    assert!(matches!(
        rendezvous.handoff_writer_endpoint(reused_transport, &sender_authority),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
}
