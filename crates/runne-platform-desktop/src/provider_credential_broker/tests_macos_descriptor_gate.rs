#[cfg(target_os = "macos")]
#[test]
fn macos_descriptor_receive_fails_closed_before_receiving_a_descriptor() {
    let (mut receiver, mut sender) = std::os::unix::net::UnixStream::pair().unwrap();
    let (endpoint, _) = std::os::unix::net::UnixStream::pair().unwrap();
    super::unix_descriptor::send_descriptor(&mut sender, &endpoint, &[0; 160]).unwrap();

    assert!(matches!(
        super::unix_descriptor::receive_descriptor::<160>(&mut receiver),
        Err(runne_platform_ports::provider_credential_broker::BrokerHandoffError::Unavailable)
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_daemon_endpoint_receive_fails_closed_before_descriptor_admission() {
    let (receiver, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = runne_api::LaunchSecret::from_bytes([23; 32])
        .unwrap()
        .derive_keys();
    let authenticator =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);

    assert!(matches!(
        super::receive_daemon_owned_writer_endpoint(receiver, &authenticator, [1; 32], [2; 32]),
        Err(runne_platform_ports::provider_credential_broker::BrokerHandoffError::Unavailable)
    ));
}
