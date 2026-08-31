//! Happy path: endpoint transfer, writer evidence, kill exchange, ack.

use runne_api::{ProviderCredentialBrokerHandoffFrame, ProviderCredentialBrokerKillBindingV1};
use runne_platform_desktop::provider_credential_broker::{
    prepare_daemon_owned_writer_endpoint_handoff, send_test_daemon_owned_writer_evidence,
};
use std::io::Write as _;
use std::net::Shutdown;

use super::enrollment_v3_broker_tests::{
    NOW, broker_fixture, graceful_shutdown, offer_transport_half, read_frame, read_to_end,
    relinquished_wire, writer_kill_key,
};

#[test]
fn v3_control_completes_the_full_broker_writer_handoff() {
    let mut fixture = broker_fixture();
    let kill_signing_key = writer_kill_key(44);
    let own_start =
        runne_platform_desktop::provider_credential_broker::test_only_observe_process_start(
            std::process::id(),
        )
        .unwrap();

    // Purpose 1: endpoint transfer; the writer would consume the offered half.
    let endpoint_half = offer_transport_half(
        &mut fixture,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        [15; 16],
    );
    // In production the writer inherits this half; here it is simply kept
    // open so the daemon's SCM_RIGHTS send has a live peer.
    let _kept_transport = prepare_daemon_owned_writer_endpoint_handoff(
        endpoint_half,
        &fixture.desktop,
        fixture.binding,
        fixture.publication_public_key,
    )
    .unwrap();

    // Purpose 2: writer evidence measured against this exact process peer.
    let evidence_half = offer_transport_half(
        &mut fixture,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE,
        [16; 16],
    );
    let release_tuple = {
        let (owned, _, _) = super::enrollment_v3_tests::owned_and_sessions();
        *owned.enrollment_binding().release_tuple_digest()
    };
    send_test_daemon_owned_writer_evidence(
        evidence_half,
        &fixture.desktop,
        [
            own_start,
            [12; 32],
            release_tuple,
            fixture.binding,
            fixture.publication_public_key,
            kill_signing_key.verifying_key().to_bytes(),
        ],
    )
    .unwrap();

    // Purpose 3: kill exchange; the daemon captures this process as the peer.
    let mut kill_half = offer_transport_half(
        &mut fixture,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
        [17; 16],
    );
    let ready_wire = read_to_end(&mut kill_half);
    assert_eq!(ready_wire.len(), 224);
    let kill_binding = ProviderCredentialBrokerKillBindingV1::new(
        own_start,
        [12; 32],
        release_tuple,
        fixture.binding,
        fixture.publication_public_key,
        kill_signing_key.verifying_key().to_bytes(),
    );
    let wire = relinquished_wire(kill_binding, &kill_signing_key);
    kill_half.write_all(&wire).unwrap();
    let _ = kill_half.shutdown(Shutdown::Write);

    // The daemon proves the completed exchange with the final ack frame.
    let ack_frame = read_frame(&mut fixture.client);
    ProviderCredentialBrokerHandoffFrame::decode_and_verify(
        &ack_frame,
        &fixture.desktop,
        &fixture.context,
        ProviderCredentialBrokerHandoffFrame::PHASE_ACK,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
        [17; 16],
        NOW,
    )
    .unwrap();

    graceful_shutdown(fixture);
}
