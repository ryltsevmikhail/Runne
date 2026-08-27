use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialProviderV2, ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialLifecycleSnapshot, CredentialOperationId,
    CredentialReadinessRevision, ProviderId,
};

use super::coordinator::ProviderCredentialBeginAdmission;
use super::{ProviderCredentialAdmission, ProviderCredentialOperationHandleIssuer};

pub(crate) use begin_admission_support::context;

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

mod begin_admission;
#[path = "tests/begin_admission_support.rs"]
pub(crate) mod begin_admission_support;
mod broker;
#[path = "tests/broker_support.rs"]
mod broker_support;
mod recovery;
mod verified_frames;
#[path = "tests/verified_frames_support.rs"]
mod verified_frames_support;
