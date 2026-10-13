use super::super::coordinator::ProviderCredentialBeginAdmission;
use super::begin_admission_support::context;
use super::verified_frames_support::{
    FIXTURE_NOW_SECONDS, command, fixture, fixture_with_store_clock, session, session_with,
    snapshot,
};
use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialEnrollmentHostError, ProviderCredentialProviderV2,
};

#[test]
fn verified_frames_admit_into_durable_begin_once() {
    let session = session([11; 32]);
    let bound = fixture([11; 32]);
    let context = context();

    let admission = bound
        .gate
        .admit(&session, &command(), &context, snapshot(), &bound.store)
        .unwrap();

    let ProviderCredentialBeginAdmission::FreshWinner(effect) = admission else {
        panic!("first verified frame pair must win the durable begin");
    };
    assert_eq!(
        effect
            .operation()
            .allocated_credential_version()
            .unwrap()
            .version(),
        1
    );
}

#[test]
fn verified_frame_replay_returns_the_original_projection_without_a_second_effect() {
    let session = session([12; 32]);
    let bound = fixture([12; 32]);
    let context = context();

    let first = bound
        .gate
        .admit(&session, &command(), &context, snapshot(), &bound.store)
        .unwrap();
    let ProviderCredentialBeginAdmission::FreshWinner(effect) = first else {
        panic!("first verified frame pair must win the durable begin");
    };
    let operation = effect.consume();
    let replay = bound
        .gate
        .admit(&session, &command(), &context, snapshot(), &bound.store)
        .unwrap();

    let ProviderCredentialBeginAdmission::ExactReplay(replay) = replay else {
        panic!("replayed verified frames must not mint a second effect authority");
    };
    assert_eq!(operation.operation_id(), replay.operation_id());
}

#[test]
fn verified_frames_from_another_authenticator_domain_are_rejected_before_the_store() {
    let session = session([13; 32]);
    let bound = fixture([14; 32]);
    let context = context();

    let error = bound
        .gate
        .admit(&session, &command(), &context, snapshot(), &bound.store)
        .err()
        .expect("foreign-domain frames must be rejected");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::AccessDenied
    ));
}

#[test]
fn expired_verified_frames_are_rejected_before_the_store() {
    let session = session([15; 32]);
    let bound = fixture([15; 32]);
    let context = context();

    let error = bound
        .gate
        .admit_at(
            &session,
            session.expires_at + 1,
            &command(),
            &context,
            snapshot(),
            &bound.store,
        )
        .err()
        .expect("expired frames must be rejected");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::AccessDenied
    ));
}

#[test]
fn live_frames_with_a_stale_store_clock_are_refused_at_the_durable_begin() {
    // Frames decode as live at the fixture decode instant, but the store's
    // verification clock already covers the begin high-water expiry: the
    // mixed clock domain must surface as Conflict (StaleLease mapped by the
    // effect authority), never as a second durable effect.
    let session = session([19; 32]);
    let bound = fixture_with_store_clock([19; 32], FIXTURE_NOW_SECONDS + 21);
    let context = context();

    let error = bound
        .gate
        .admit(&session, &command(), &context, snapshot(), &bound.store)
        .err()
        .expect("a store clock past the begin high-water must refuse the begin");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::Conflict
    ));
}

#[test]
fn live_frames_at_the_exact_ttl_edge_are_refused_at_the_durable_begin() {
    // effective_now == begin high-water expiry is already expired: the store
    // refuses at the exact 20-second fixture TTL edge.
    let session = session([20; 32]);
    let bound = fixture_with_store_clock([20; 32], FIXTURE_NOW_SECONDS + 20);
    let context = context();

    let error = bound
        .gate
        .admit(&session, &command(), &context, snapshot(), &bound.store)
        .err()
        .expect("the exact TTL edge must refuse the begin");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::Conflict
    ));
}

#[test]
fn tampered_admission_frame_is_rejected_before_the_store() {
    let mut session = session([16; 32]);
    let last = session.admission_frame.len() - 1;
    session.admission_frame[last] ^= 0x01;
    let bound = fixture([16; 32]);
    let context = context();

    let error = bound
        .gate
        .admit(&session, &command(), &context, snapshot(), &bound.store)
        .err()
        .expect("tampered frames must be rejected");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::AccessDenied
    ));
}

#[test]
fn command_substitution_under_a_live_envelope_is_rejected_before_the_store() {
    let substituted = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Revoke,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
        "intent-a",
    )
    .unwrap();
    let session = session_with([17; 32], &substituted, &context());
    let bound = fixture([17; 32]);
    let context = context();

    let error = bound
        .gate
        .admit(&session, &command(), &context, snapshot(), &bound.store)
        .err()
        .expect("command substitution must be rejected");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::AccessDenied
    ));
}

#[test]
fn native_intent_substitution_under_a_live_envelope_is_rejected_before_the_store() {
    let substituted = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
        "intent-b",
    )
    .unwrap();
    let session = session([18; 32]);
    let bound = fixture([18; 32]);
    let context = context();

    let error = bound
        .gate
        .admit(&session, &substituted, &context, snapshot(), &bound.store)
        .err()
        .expect("native intent substitution must be rejected");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::AccessDenied
    ));
}
