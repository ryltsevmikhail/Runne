use std::sync::Arc;

use runne_api::{ProviderCredentialEnrollmentHostError, ProviderCredentialProviderV2};
use runne_http::ProviderCredentialEnrollmentHttpAdmissionResolver;

use super::protected_session_tests::{control, id};
use super::{DaemonProviderCredentialEnrollmentControl, ProtectedEnrollmentSessionFacts};

type Resolver = super::super::http_admission_resolver::LiveCredentialHttpAdmissionResolver;

fn resolver(control: &Arc<DaemonProviderCredentialEnrollmentControl>) -> Resolver {
    Resolver::new(
        control.http_authority_issuer.clone(),
        Arc::clone(&control.http_facts),
    )
}

fn assert_status_error(
    resolver: &Resolver,
    session: [u8; 16],
    expected: ProviderCredentialEnrollmentHostError,
) {
    assert!(matches!(
        resolver.resolve_status(session, &ProviderCredentialProviderV2::DeepSeek),
        Err(error) if error == expected
    ));
}

#[test]
fn http_status_resolver_denies_cold_wrong_and_revoked_sessions() {
    let (control, _) = control();
    let facts = ProtectedEnrollmentSessionFacts::for_test();
    let resolver = resolver(&control);
    assert_status_error(
        &resolver,
        id(2),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );
    control.publish_http_facts(facts).unwrap();
    assert_status_error(
        &resolver,
        id(3),
        ProviderCredentialEnrollmentHostError::AccessDenied,
    );
    assert!(
        resolver
            .resolve_status(id(2), &ProviderCredentialProviderV2::DeepSeek)
            .is_ok()
    );
    control.clear_http_facts(id(2));
    assert_status_error(
        &resolver,
        id(2),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );
}

#[test]
fn protected_session_drop_revokes_its_current_http_facts() {
    let (control, keys) = control();
    let facts = ProtectedEnrollmentSessionFacts::for_test();
    control.publish_http_facts(facts.clone()).unwrap();
    let rendezvous =
        super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let session = control
        .start_test_protected_session(&keys, facts, rendezvous)
        .unwrap();
    drop(session);
    assert_status_error(
        &resolver(&control),
        id(2),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );
}

#[test]
fn renewal_then_next_round_keeps_replacement_http_facts_until_its_drop() {
    let (control, keys) = control();
    let facts_a = ProtectedEnrollmentSessionFacts::for_test();
    let mut session_a = control
        .start_test_protected_session(
            &keys,
            facts_a.clone(),
            super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
        )
        .unwrap();
    control.publish_http_facts(facts_a).unwrap();

    let facts_b = ProtectedEnrollmentSessionFacts::for_test_with_session(id(4));
    session_a.refresh_test_http_facts(facts_b.clone()).unwrap();
    session_a.clear_http_facts();
    drop(session_a);
    assert_status_error(
        &resolver(&control),
        id(4),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );

    let session_b = control
        .start_test_protected_session(
            &keys,
            facts_b.clone(),
            super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
        )
        .unwrap();
    control.publish_http_facts(facts_b).unwrap();
    assert!(
        resolver(&control)
            .resolve_status(id(4), &ProviderCredentialProviderV2::DeepSeek)
            .is_ok()
    );
    drop(session_b);
    assert_status_error(
        &resolver(&control),
        id(4),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );
}
