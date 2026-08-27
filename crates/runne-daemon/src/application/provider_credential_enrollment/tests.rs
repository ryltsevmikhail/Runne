use runne_api::{
    ApiActor, ApiPrincipalId, BeginProviderCredentialEnrollment,
    ProviderCredentialBeginIntentBinding, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialProviderV2, ProviderCredentialRequestAuthorityPair,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialLifecycleSnapshot, CredentialOperationId,
    CredentialReadinessRevision, ProviderId,
};

use super::coordinator::ProviderCredentialBeginAdmission;
use super::{ProviderCredentialAdmission, ProviderCredentialOperationHandleIssuer};

#[test]
fn effect_authority_has_no_direct_store_begin_path() {
    const EFFECT: &str = include_str!("effect_authority.rs");

    assert!(
        !EFFECT.contains("store.begin("),
        "the effect authority must only carry an already admitted winner"
    );
}

#[test]
fn concurrent_begin_proof_returns_one_effect_authority_and_one_idempotent_projection() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
        "intent-a",
    )
    .unwrap();
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    let snapshot = CredentialLifecycleSnapshot::new(
        ProviderId::new("openai").unwrap(),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        1,
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (lifecycle_authority, _) = CredentialAuthorityPair::new().split();
    let (enrollment_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("admission.sqlite"),
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    let admission = ProviderCredentialAdmission::new(verifier, measurements);
    let first = admission
        .admit_begin(
            &authority,
            &proof,
            &command,
            &context,
            snapshot.clone(),
            &store,
        )
        .unwrap();
    let replay = admission
        .admit_begin(&authority, &proof, &command, &context, snapshot, &store)
        .unwrap();
    let operation = match first {
        ProviderCredentialBeginAdmission::FreshWinner(effect) => effect.consume(),
        ProviderCredentialBeginAdmission::ExactReplay(_) => panic!("first admission must win"),
    };
    let replay = match replay {
        ProviderCredentialBeginAdmission::FreshWinner(_) => {
            panic!("replay must not mint authority")
        }
        ProviderCredentialBeginAdmission::ExactReplay(snapshot) => snapshot,
    };
    assert_eq!(operation.operation_id(), replay.operation_id());
}

#[test]
fn restart_begin_proof_replay_returns_projection_and_zero_repeated_effects() {
    const EFFECT: &str = include_str!("effect_authority.rs");
    assert!(
        !EFFECT.contains("BeginCredentialOperation"),
        "the effect authority must represent an admitted winner, not a pending store request"
    );
}

#[test]
fn operation_handle_requires_the_daemon_hmac_before_store_lookup() {
    let issuer = ProviderCredentialOperationHandleIssuer::new([9; 32]);
    let operation_id = CredentialOperationId::from_bytes([7; 16]).unwrap();
    let handle = issuer.issue(operation_id);
    let foreign = ProviderCredentialOperationHandleIssuer::new([8; 32]);

    assert_eq!(issuer.resolve(handle), Ok(operation_id));
    assert_eq!(
        foreign.resolve(handle),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn broker_claim_binding_rejects_a_foreign_transport_authority_before_admission() {
    let (_, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let (foreign_issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = foreign_issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let admission = admission(verifier);

    assert_eq!(
        admission.require_base(&authority),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn broker_claim_binding_rejects_a_foreign_intent_proof_before_admission() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let (foreign_issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let proof = foreign_issuer
        .issue_intent_proof([6; 32], [7; 32], [8; 32], [9; 32], 10)
        .unwrap();
    let admission = admission(verifier);

    admission.require_base(&authority).unwrap();
    assert_eq!(
        admission.require_intent(&proof),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn broker_claim_binding_rejects_a_session_substituted_intent_proof() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let proof = issuer
        .issue_intent_proof([6; 32], [7; 32], [8; 32], [9; 32], 10)
        .unwrap();
    let admission = admission(verifier);

    assert_eq!(
        admission.require_begin(&authority, &proof),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn broker_claim_binding_accepts_the_exact_protected_session() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let proof = issuer
        .issue_intent_proof([6; 32], [3; 32], [8; 32], [9; 32], 10)
        .unwrap();
    let admission = admission(verifier);

    admission.require_begin(&authority, &proof).unwrap();
}

#[test]
fn broker_claim_binding_rejects_another_begin_command_in_the_same_session() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let expected = begin(ProviderCredentialEnrollmentActionV2::Pair);
    let substituted = begin(ProviderCredentialEnrollmentActionV2::Revoke);
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&substituted, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            10,
        )
        .unwrap();
    let admission = admission(verifier);

    assert_eq!(
        admission.require_begin_command(&authority, &proof, &expected, &context),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn daemon_begin_allocates_the_operation_id_and_authoritative_next_version() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = begin(ProviderCredentialEnrollmentActionV2::Pair);
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            10,
        )
        .unwrap();
    let snapshot = lifecycle_snapshot();
    let admission = admission(verifier);

    let effect = admission
        .begin_input(&authority, &proof, &command, &context, snapshot)
        .unwrap();

    assert_eq!(effect.allocated_credential_version().unwrap().version(), 9);
}

fn lifecycle_snapshot() -> CredentialLifecycleSnapshot {
    CredentialLifecycleSnapshot::new(
        ProviderId::new("openai").unwrap(),
        None,
        CredentialLifecycleRevision::new(7).unwrap(),
        CredentialFence::new(4).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        9,
    )
    .unwrap()
}

fn begin(action: ProviderCredentialEnrollmentActionV2) -> BeginProviderCredentialEnrollment {
    BeginProviderCredentialEnrollment::new(
        action,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
        "intent-a",
    )
    .unwrap()
}

fn context() -> ProviderCredentialCommandContext {
    ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes([1; 16]),
        idempotency_key: IdempotencyKey::new("context-a").unwrap(),
        principal: ApiPrincipalId::new("principal-a").unwrap(),
        actor: ApiActor::new("actor-a").unwrap(),
    }
}

fn admission(
    verifier: runne_api::ProviderCredentialRequestAuthorityVerifier,
) -> ProviderCredentialAdmission {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    ProviderCredentialAdmission::new(verifier, measurements)
}

mod recovery;
