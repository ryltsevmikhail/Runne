use std::sync::Arc;

use runne_provider::{CredentialBindingDigest, CredentialMeasurementSnapshot};

use super::super::claim_fenced_writer_on;
use super::DaemonProtectedCredentialEnrollmentSession;
use super::connected_release_fixture::verified_release;
use super::connected_test_support::UnixQualifiedChannel;
use crate::application::provider_credential_enrollment::broker::{
    CredentialBrokerChannel, ProviderCredentialBroker,
};
use crate::protected_activation::control_v3::initial_exchange::session_test_support::{
    connected_qualification_fixture, owned_for_test,
};

#[test]
fn fenced_writer_uses_real_receiver_ack_then_service_handoff_and_pair_relay() {
    exchange(false);
}

#[test]
fn mutated_bundle_emits_no_ack_publication_or_service_effect() {
    exchange(true);
}

fn exchange(mutate_admission: bool) {
    let owned = owned_for_test();
    let (mut session, keys, database) =
        crate::protected_activation::control_v3::initial_exchange::session_test_support::session(
            false,
        );
    let (installed_fixture, admission, mut verifier, receiver_fixture, fence_now) =
        connected_qualification_fixture(&owned, verified_release()).into_parts();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    session.installed_facts = Some(installed_fixture);
    session = session.retain_qualification(admission).unwrap();
    let command = super::tests::command(runne_api::ProviderCredentialEnrollmentActionV2::Pair);
    session
        .accept_initial_request(
            &super::tests::request(&session, &keys, &command),
            now * 1_000,
        )
        .unwrap();
    let codec =
        runne_api::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    session
        .begin(
            &codec.encode_desktop_begin(&command, 1).unwrap(),
            now * 1_000,
        )
        .unwrap();
    let installed = session.take_installed_facts().unwrap();
    let continuation = CredentialBindingDigest::from_measured([31; 32]).unwrap();
    let committed = session
        .commit_qualification(&owned, &installed, continuation, &mut verifier, fence_now)
        .unwrap();
    let accepted_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    session
        .accept_qualification_fence(committed, &owned, accepted_at)
        .unwrap();
    let delivery = session
        .qualification_fenced
        .take()
        .unwrap()
        .into_writer_delivery()
        .unwrap();
    let (mut channel, receiver, service) =
        UnixQualifiedChannel::new(receiver_fixture, mutate_admission);
    let coordinator = ProviderCredentialBroker::new(Arc::new(session.control.measurements.clone()));
    let measurements = measurements(&session, continuation, channel.binding_digest().as_bytes());
    let context = coordinator
        .claim_issue_context(
            measurements.clone(),
            channel.binding_digest().as_bytes(),
            continuation,
            session.facts.database_generation,
            session.facts.supervisor_generation,
        )
        .unwrap();

    let pending = claim_fenced_writer_on(
        &mut session,
        delivery,
        coordinator,
        context,
        measurements,
        continuation,
        &mut channel,
        Some(&service),
    );
    let issued = channel.original_ticket_digest().unwrap();
    let connection = rusqlite::Connection::open(super::tests::broker_db(&database)).unwrap();
    for table in [
        "provider_qualification_admission_fences",
        "provider_credential_ticket_attempts",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1,
            "{table} must contain exactly one durable record"
        );
    }
    let stored: Vec<u8> = connection
        .query_row(
            "SELECT ticket_digest FROM provider_credential_ticket_attempts WHERE attempt=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stored, issued,
        "the original ticket digest is durable and exact"
    );
    if mutate_admission {
        let events = channel.events();
        assert!(pending.is_err());
        assert!(!channel.acknowledged());
        assert!(!events.contains(&"ack"));
        assert!(!events.contains(&"claim-accepted"));
        assert!(!events.contains(&"publication"));
        assert!(!events.contains(&"service-arm"));
        assert!(!events.contains(&"service-handoff"));
        UnixQualifiedChannel::join(receiver, false);
    } else {
        let pending = pending.unwrap();
        assert!(
            channel.acknowledged(),
            "provider receiver emitted its transport-bound ACK"
        );
        assert!(
            pending.relay().is_some(),
            "PAIR preserves its relay publication"
        );
        UnixQualifiedChannel::join(receiver, true);
        let events = channel.events();
        assert_before(&events, "ack", "claim-accepted");
        assert_before(&events, "claim-accepted", "publication");
        assert_before(&events, "publication", "service-arm");
        assert_before(&events, "service-arm", "service-handoff");
        assert!(events.contains(&"receiver-accepted"));
    }
}

fn measurements(
    session: &DaemonProtectedCredentialEnrollmentSession,
    continuation: CredentialBindingDigest,
    channel: [u8; 32],
) -> CredentialMeasurementSnapshot {
    let authority = &session.control.measurements;
    CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([10; 32]).unwrap(),
        authority.release_manifest_digest([11; 32]).unwrap(),
        authority.desktop_executable_identity([12; 32]).unwrap(),
        authority.writer_executable_identity([13; 32]).unwrap(),
        authority.reader_executable_identity([14; 32]).unwrap(),
        authority.contract_bundle_digest([15; 32]).unwrap(),
        authority.daemon_authority_id([16; 32]).unwrap(),
        authority.protected_session_id([17; 32]).unwrap(),
        authority
            .desktop_supervisor_generation(session.facts.supervisor_generation)
            .unwrap(),
        authority.writer_launch_id([18; 32]).unwrap(),
        authority.writer_process_start_identity([19; 32]).unwrap(),
        authority.writer_process_handle_identity([20; 32]).unwrap(),
        authority.broker_channel_binding(channel).unwrap(),
        authority
            .continuation_binding_digest(continuation.as_bytes())
            .unwrap(),
    )
    .unwrap()
}

fn assert_before(events: &[&str], earlier: &str, later: &str) {
    let index = |event| events.iter().position(|current| *current == event).unwrap();
    assert!(index(earlier) < index(later), "{events:?}");
}
