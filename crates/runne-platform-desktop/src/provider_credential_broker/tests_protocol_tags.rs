use std::io::Write as _;
use std::net::Shutdown;

use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};

use super::*;

#[cfg(unix)]
#[test]
fn daemon_endpoint_rejects_a_challenge_replayed_without_the_publication_key() {
    let (sender, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (_, endpoint) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([22; 32]).unwrap().derive_keys();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let authority =
        runne_api::ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(
            authenticator.clone(),
        );
    let mut challenge = [0; 96];
    challenge[..32].copy_from_slice(&[5; 32]);
    challenge[32..64].copy_from_slice(&[6; 32]);
    let proof = authenticator.authenticate_transfer(&challenge[..64]);
    challenge[64..].copy_from_slice(&proof);
    peer.write_all(&challenge).unwrap();
    peer.shutdown(Shutdown::Write).unwrap();

    assert!(matches!(
        send_daemon_owned_writer_endpoint(sender, endpoint, &authority, [5; 32], [7; 32]),
        Err(BrokerHandoffError::Rejected)
    ));
}
