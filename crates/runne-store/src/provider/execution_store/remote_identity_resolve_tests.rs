use runne_provider::ProviderId;

use super::super::credential_lifecycle::online_test_support::complete_pair;
use super::ProviderAuthorityIssueOutcome;
use super::authority_test_support::{Fixture, prepare_request_for_provider};
use super::secondary_profile_grant_tests;

#[test]
fn resolves_full_secondary_attempt_from_exact_admission_and_effect_start() {
    let (mut fixture, lifecycle) = Fixture::new_with_online_credentials(100, |store| {
        complete_pair(store, 77, "remote-binding-resolve");
    });
    fixture.config.profile_digest = [22; 32];
    fixture.config.pricing_revision_digest = [33; 32];
    fixture.install();
    let grant = secondary_profile_grant_tests::grant(&fixture, "openai");
    let request = prepare_request_for_provider(fixture.launch(), &fixture.path, 91, "openai");
    let admission = match fixture
        .store
        .issue_secondary_profile(fixture.launch(), &grant, &request)
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission expected"),
    };
    let authorization = lifecycle
        .authorize_online_dispatch(fixture.launch(), admission.claim(), 100)
        .unwrap();
    let (_, credential) = authorization.split();
    fixture
        .store
        .start_online_effect(fixture.launch(), admission.claim(), &credential)
        .unwrap();

    let binding = fixture
        .store
        .resolve_remote_attempt_binding(
            admission.claim(),
            &ProviderId::new("openai").unwrap(),
            &ProviderId::new("openai").unwrap(),
            "background-text-v1",
        )
        .unwrap();
    assert_eq!(binding.taskrun_id, request.taskrun_id);
    assert_eq!(binding.taskrun_attempt_id, request.execution_attempt_id);
    assert_eq!(binding.dispatch_attempt_id, admission.claim().attempt_id);
    assert_eq!(binding.provider_id, "openai");
    assert_eq!(binding.credential_realm, "openai");
    assert_eq!(binding.profile_id, "background-text-v1");
    assert_eq!(binding.profile_digest, [2; 32]);
    assert_eq!(binding.pricing_digest, [3; 32]);
    assert_eq!(binding.prepared_digest, admission.claim().prepared_digest);
    assert_eq!(binding.request_digest, admission.claim().render_digest);

    let reject_claim = |claim: runne_provider::ProviderDispatchClaim| {
        assert!(
            fixture
                .store
                .resolve_remote_attempt_binding(
                    &claim,
                    &ProviderId::new("openai").unwrap(),
                    &ProviderId::new("openai").unwrap(),
                    "background-text-v1",
                )
                .is_err()
        );
    };
    let mut wrong_permit = admission.claim().clone();
    wrong_permit.permit_id[0] ^= 1;
    reject_claim(wrong_permit);
    let mut wrong_call = admission.claim().clone();
    wrong_call.call_id = runne_provider::ProviderCallId::from_bytes([92; 16]);
    reject_claim(wrong_call);
    let mut wrong_token_reservation = admission.claim().clone();
    wrong_token_reservation.token_reservation_id[0] ^= 1;
    reject_claim(wrong_token_reservation);
    let mut wrong_cost_reservation = admission.claim().clone();
    wrong_cost_reservation.cost_reservation_id[0] ^= 1;
    reject_claim(wrong_cost_reservation);
    let mut wrong_idempotency = admission.claim().clone();
    wrong_idempotency.provider_idempotency_key.push('x');
    reject_claim(wrong_idempotency);
    let mut wrong_fence = admission.claim().clone();
    wrong_fence.fencing_token += 1;
    reject_claim(wrong_fence);
}

#[test]
fn resolves_full_primary_attempt_without_secondary_grant() {
    let (mut fixture, lifecycle) = Fixture::new_with_online_credentials(100, |store| {
        complete_pair(store, 78, "remote-binding-primary");
    });
    fixture.config.profile_digest = [2; 32];
    fixture.config.pricing_revision_digest = [3; 32];
    fixture.install();
    let request = prepare_request_for_provider(fixture.launch(), &fixture.path, 92, "openai");
    let admission = match fixture.store.issue(fixture.launch(), &request).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission expected"),
    };
    let authorization = lifecycle
        .authorize_online_dispatch(fixture.launch(), admission.claim(), 100)
        .unwrap();
    let (_, credential) = authorization.split();
    fixture
        .store
        .start_online_effect(fixture.launch(), admission.claim(), &credential)
        .unwrap();

    let binding = fixture
        .store
        .resolve_remote_attempt_binding(
            admission.claim(),
            &ProviderId::new("openai").unwrap(),
            &ProviderId::new("openai").unwrap(),
            "gocode-openai-responses-text/1",
        )
        .unwrap();
    assert_eq!(binding.taskrun_id, request.taskrun_id);
    assert_eq!(binding.taskrun_attempt_id, request.execution_attempt_id);
    assert_eq!(binding.dispatch_attempt_id, admission.claim().attempt_id);
    assert_eq!(binding.provider_id, "openai");
    assert_eq!(binding.credential_realm, "openai");
    assert_eq!(binding.profile_id, "gocode-openai-responses-text/1");
    assert_eq!(binding.profile_digest, [2; 32]);
    assert_eq!(binding.pricing_digest, [3; 32]);
    assert_eq!(binding.prepared_digest, admission.claim().prepared_digest);
    assert_eq!(binding.request_digest, admission.claim().render_digest);

    assert!(
        fixture
            .store
            .resolve_remote_attempt_binding(
                admission.claim(),
                &ProviderId::new("openai-background").unwrap(),
                &ProviderId::new("openai-background").unwrap(),
                "gocode-openai-responses-background-text/1",
            )
            .is_err()
    );
}
