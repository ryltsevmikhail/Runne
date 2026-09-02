use runne_api::{
    LaunchSecret, ProtectedCredentialEnrollmentAdmissionBinding,
    ProtectedCredentialEnrollmentAuthenticator, ProtectedCredentialEnrollmentControlFrame,
    ProtectedCredentialEnrollmentRequestBinding, ProviderCredentialRequestAuthorityIssuer,
    ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialBindingDigest, CredentialInstallationOwnerId, CredentialOperationId,
};

use crate::application::provider_credential_enrollment::operation_handle::ProviderCredentialOperationHandleIssuer;

use super::{
    PendingBrokerEndpointHandoff, PendingBrokerRendezvousBinding, PendingBrokerRendezvousRegistry,
};
use crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous;

#[test]
fn restarted_registry_has_no_live_rendezvous_authority() {
    let registry =
        PendingBrokerRendezvousRegistry::new(ProviderCredentialOperationHandleIssuer::new([9; 32]));
    let operation = CredentialOperationId::from_bytes([1; 16]).unwrap();

    assert!(!registry.has_live(operation, 1));
}

#[cfg(feature = "desktop-protected")]
#[test]
fn matching_foreign_transfer_key_is_rejected_before_endpoint_handoff() {
    let (issuer_a, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority_a = issuer_a
        .issue_base([3; 32], [7; 32], [4; 32], 1, [6; 32], 1, [5; 32])
        .unwrap();
    let binding = PendingBrokerRendezvousBinding {
        operation_id: CredentialOperationId::from_bytes([1; 16]).unwrap(),
        begin_proof: CredentialBindingDigest::from_measured([2; 32]).unwrap(),
        owner: CredentialInstallationOwnerId::from_bytes([3; 32]).unwrap(),
        protected_session: [4; 32],
        tauri_peer: [5; 32],
        daemon_authority: [6; 32],
        database_generation: 1,
        supervisor_generation: 1,
        release_tuple: CredentialBindingDigest::from_measured([7; 32]).unwrap(),
        expires_at_high_water: 1_000,
    };
    let handoff = PendingBrokerEndpointHandoff {
        binding,
        authority_witness: authority_a.credential_broker_handoff_witness(),
        broker_transfer: None,
        rendezvous: DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
    };
    let (issuer_b, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let transfer = verified_transfer_authority(&issuer_b, [13; 32], [4; 32]);
    let (sender, _receiver) = std::os::unix::net::UnixStream::pair().unwrap();

    assert!(handoff.send_endpoint(sender, transfer).is_err());
}

#[cfg(feature = "desktop-protected")]
#[test]
fn transfer_authority_requires_the_same_daemon_issuer_and_session() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([3; 32], [7; 32], [4; 32], 1, [6; 32], 1, [5; 32])
        .unwrap();
    let witness = authority.credential_broker_handoff_witness();
    let transfer = verified_transfer_authority(&issuer, [13; 32], [4; 32]);

    assert!(transfer.matches_handoff(&witness, &[4; 32]));
    assert!(!transfer.matches_handoff(&witness, &[8; 32]));
}

#[cfg(feature = "desktop-protected")]
fn verified_transfer_authority(
    issuer: &ProviderCredentialRequestAuthorityIssuer,
    secret: [u8; 32],
    protected_session: [u8; 32],
) -> runne_api::ProviderCredentialBrokerTransferAuthority {
    let keys = LaunchSecret::from_bytes(secret).unwrap().derive_keys();
    let authenticator =
        ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
    let request_binding = ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        uuid(2),
        uuid(3),
        1,
        1,
        uuid(4),
        [7; 32],
        [5; 32],
        [9; 32],
        [10; 32],
        [11; 32],
        [12; 32],
        [13; 32],
        100_000,
        120_000,
    )
    .unwrap();
    let request_frame = ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator
            .issue_request(request_binding.clone(), 1)
            .unwrap(),
    )
    .encode_frame();
    let request = authenticator
        .decode_request(&request_frame, &request_binding, 0, 110_000)
        .unwrap();
    let admission_binding = ProtectedCredentialEnrollmentAdmissionBinding::new(
        [3; 32],
        [7; 32],
        protected_session,
        1,
        [6; 32],
        1,
        [5; 32],
        [9; 32],
        [10; 32],
        uuid(5),
        120_000,
    )
    .unwrap();
    let admission_frame = ProtectedCredentialEnrollmentControlFrame::Admission(
        authenticator
            .issue_admission(&request, admission_binding.clone(), 2)
            .unwrap(),
    )
    .encode_frame();
    let admission = authenticator
        .decode_admission(&admission_frame, &request, &admission_binding, 1, 110_000)
        .unwrap();
    let admission = keys.bind_credential_broker_transfer(admission).unwrap();
    let (_, _, transfer) = issuer
        .issue_from_verified_enrollment_with_broker_transfer(request, admission)
        .unwrap();
    transfer
}

#[cfg(feature = "desktop-protected")]
const fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}
