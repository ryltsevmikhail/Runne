//! Rejection paths: purpose order, binding, freshness, and MAC failures.

use std::io::Write as _;

use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchAuthorityError,
    ProviderCredentialBrokerHandoffFrame,
};
use runne_platform_desktop::provider_credential_broker::send_test_daemon_owned_writer_evidence;

use super::enrollment_v3_broker_tests::{
    broker_fixture, offer_transport_half, write_offer_without_ready,
};

#[test]
fn v3_control_rejects_a_broker_offer_out_of_purpose_order() {
    let mut fixture = broker_fixture();
    // Purpose 2 arrives while purpose 1 is expected: rejected without a ready.
    write_offer_without_ready(
        &mut fixture,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE,
        [15; 16],
        500,
        25_500,
    );
    assert_eq!(
        fixture.server.join().unwrap(),
        Err(LaunchAuthorityError::InvalidContract)
    );
}

#[test]
fn v3_control_rejects_an_offer_bound_to_another_rendezvous() {
    let mut fixture = broker_fixture();
    // A stranger key domain cannot forge the desktop transfer proof.
    let stranger = CredentialBrokerTransferAuthenticator::from_protected_activation(
        &runne_api::LaunchSecret::from_bytes([91; 32])
            .unwrap()
            .derive_keys(),
    );
    let offer = runne_api::ProviderCredentialBrokerHandoffFrame::offer(
        fixture.context.clone(),
        runne_api::ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        500,
        25_500,
        [15; 16],
        &stranger,
    )
    .unwrap();
    fixture.client.write_all(&offer.encode_frame()).unwrap();
    assert_eq!(
        fixture.server.join().unwrap(),
        Err(LaunchAuthorityError::ReadinessProofMismatch)
    );
}

#[test]
fn v3_control_rejects_a_stale_broker_offer() {
    let mut fixture = broker_fixture();
    // The loop clock reads 1_000; this window has already expired.
    write_offer_without_ready(
        &mut fixture,
        runne_api::ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        [15; 16],
        100,
        999,
    );
    assert_eq!(
        fixture.server.join().unwrap(),
        Err(LaunchAuthorityError::OwnershipMismatch)
    );
}

#[test]
#[cfg(target_os = "macos")]
fn v3_control_rejects_writer_evidence_from_another_release() {
    let mut fixture = broker_fixture();
    let own_start =
        runne_platform_desktop::provider_credential_broker::test_only_observe_process_start(
            std::process::id(),
        )
        .unwrap();
    let endpoint_half = offer_transport_half(
        &mut fixture,
        runne_api::ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        [15; 16],
    );
    // Keep the offered half open so the daemon's SCM_RIGHTS send has a peer.
    let _kept_transport = runne_platform_desktop::provider_credential_broker::prepare_daemon_owned_writer_endpoint_handoff(
        endpoint_half,
        &fixture.desktop,
        fixture.binding,
        fixture.publication_public_key,
    )
    .unwrap();

    let evidence_half = offer_transport_half(
        &mut fixture,
        runne_api::ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE,
        [16; 16],
    );
    // Evidence claims another release tuple than the enrollment binding.
    // The sender itself completes; the daemon rejects the frame on receipt.
    send_test_daemon_owned_writer_evidence(
        evidence_half,
        &fixture.desktop,
        [
            own_start,
            [12; 32],
            [77; 32],
            fixture.binding,
            fixture.publication_public_key,
            [13; 32],
        ],
    )
    .unwrap();

    // The daemon consumed the mismatched evidence and terminated fail-closed.
    assert_eq!(
        fixture.server.join().unwrap(),
        Err(LaunchAuthorityError::OwnershipMismatch)
    );
}
