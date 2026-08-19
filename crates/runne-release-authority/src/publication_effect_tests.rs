//! Candidate-global publication-effect ledger: claim/replay/transition/reconciliation.

use crate::Digest;
use crate::publication_effect_ledger::FixturePublicationEffectLedger;
use crate::publication_effect_types::{
    PublicationEffectError, PublicationEffectScope, PublicationEffectState, ReconcileOutcome,
};

fn pub_scope(promotion: &str, namespace: &str, generation: u64) -> PublicationEffectScope {
    PublicationEffectScope {
        authority_instance: Digest::fixture([1; 32]),
        promotion: promotion.into(),
        candidate_digest: Digest::fixture([2; 32]),
        rc3_authorization_digest: Digest::fixture([3; 32]),
        manifest_digest: Digest::fixture([4; 32]),
        final_review_digest: Digest::fixture([5; 32]),
        allowlist_digest: Digest::fixture([6; 32]),
        allowlist_generation: 1,
        destination: "github".into(),
        channel: "release-notes".into(),
        effect_kind: "publish".into(),
        effect_scope_digest: Digest::fixture([7; 32]),
        executor: [
            "principal".into(),
            "account".into(),
            "lane".into(),
            "key".into(),
            "profile".into(),
        ],
        executable_digest: Digest::fixture([8; 32]),
        workflow_digest: Digest::fixture([9; 32]),
        idempotency_namespace: namespace.into(),
        valid_from: 10,
        expires_at: 20,
        revocation_epoch: 1,
        generation,
    }
}

#[test]
fn claim_dispatch_succeed_replay_and_reclaim_follow_the_state_machine() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let scope = pub_scope("promotion-a", "ns-1", 1);

    let dispatch = ledger.claim(&scope, 15, 1, 1).unwrap();
    assert_eq!(ledger.state("ns-1"), Some(PublicationEffectState::Claimed));

    // exact replay of the same claim is a duplicate, not a new claim
    assert_eq!(
        ledger.claim(&scope, 15, 1, 1),
        Err(PublicationEffectError::DuplicateClaim)
    );

    let dispatch = ledger.dispatch(dispatch, 15, 1, 1).unwrap();
    assert_eq!(ledger.state("ns-1"), Some(PublicationEffectState::InFlight));

    ledger.succeed(dispatch, Digest::fixture([42; 32])).unwrap();
    assert_eq!(
        ledger.state("ns-1"),
        Some(PublicationEffectState::Succeeded)
    );
    assert_eq!(ledger.settlement("ns-1"), Some(Digest::fixture([42; 32])));
}

#[test]
fn namespace_is_global_across_promotions_and_divergence_is_rejected() {
    let mut ledger = FixturePublicationEffectLedger::default();
    ledger
        .claim(&pub_scope("promotion-a", "ns-1", 1), 15, 1, 1)
        .unwrap();

    // same namespace, different promotion -> global namespace conflict
    assert_eq!(
        ledger.claim(&pub_scope("promotion-b", "ns-1", 1), 15, 1, 1),
        Err(PublicationEffectError::NamespaceAlreadyClaimed)
    );

    // same namespace + promotion, different digest -> divergent
    let mut divergent = pub_scope("promotion-a", "ns-1", 1);
    divergent.candidate_digest = Digest::fixture([99; 32]);
    assert_eq!(
        ledger.claim(&divergent, 15, 1, 1),
        Err(PublicationEffectError::DivergentClaim)
    );
}

#[test]
fn stale_or_revoked_claims_are_rejected_before_mutation() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let scope = pub_scope("promotion-a", "ns-1", 1);
    assert_eq!(
        ledger.claim(&scope, 5, 1, 1),
        Err(PublicationEffectError::AuthorizationExpiredOrRevoked)
    );
    assert_eq!(
        ledger.claim(&scope, 15, 2, 1),
        Err(PublicationEffectError::AuthorizationExpiredOrRevoked)
    );
    assert_eq!(
        ledger.claim(&scope, 15, 1, 2),
        Err(PublicationEffectError::AuthorizationExpiredOrRevoked)
    );
    assert!(ledger.is_empty());
}

#[test]
fn uncertain_reconcile_absent_then_reclaim_at_generation_plus_one() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let scope = pub_scope("promotion-a", "ns-1", 1);

    let dispatch = ledger.claim(&scope, 15, 1, 1).unwrap();
    let dispatch = ledger.dispatch(dispatch, 15, 1, 1).unwrap();
    let dispatch = ledger.mark_uncertain(dispatch).unwrap();
    assert_eq!(
        ledger.state("ns-1"),
        Some(PublicationEffectState::Uncertain)
    );

    let dispatch = ledger
        .reconcile(dispatch, ReconcileOutcome::Absent, Digest::fixture([0; 32]))
        .unwrap();
    assert_eq!(
        ledger.state("ns-1"),
        Some(PublicationEffectState::ReconciledAbsent)
    );

    let next = pub_scope("promotion-a", "ns-1", 2);
    let dispatch = ledger.reclaim(dispatch, &next, 15, 1, 1).unwrap();
    assert_eq!(ledger.state("ns-1"), Some(PublicationEffectState::Claimed));
    assert_eq!(dispatch.generation(), 2);
}

#[test]
fn invalid_transitions_and_reconciliation_bound_are_rejected() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let scope = pub_scope("promotion-a", "ns-1", 1);
    let dispatch = ledger.claim(&scope, 15, 1, 1).unwrap();

    // cannot succeed directly from Claimed
    assert_eq!(
        ledger.succeed(dispatch, Digest::fixture([42; 32])),
        Err(PublicationEffectError::InvalidState)
    );

    // bounded inconclusive readbacks lead to terminal blocked
    let mut ledger2 = FixturePublicationEffectLedger::default();
    let dispatch = ledger2.claim(&scope, 15, 1, 1).unwrap();
    let dispatch = ledger2.dispatch(dispatch, 15, 1, 1).unwrap();
    let dispatch = ledger2.mark_uncertain(dispatch).unwrap();
    ledger2
        .reconcile(
            dispatch,
            ReconcileOutcome::Inconclusive,
            Digest::fixture([0; 32]),
        )
        .unwrap();
    assert_eq!(ledger2.state("ns-1"), Some(PublicationEffectState::Blocked));
}

#[test]
fn durable_ledger_persists_claim_and_reopens_with_exact_replay() {
    use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
    let mut path = std::env::temp_dir();
    path.push(format!("publication-effect-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let scope = pub_scope("promotion-a", "ns-1", 1);
    let mut ledger =
        crate::publication_effect_durable::DurableFixturePublicationEffectLedger::create(&path)
            .unwrap();
    let context = PublicationEffectContext {
        observed_at: 15,
        revocation_epoch: 1,
        allowlist_generation: 1,
    };
    let claim = PublicationEffectCommand::claim("claim-1", &scope, context);
    let dispatch = ledger.claim_command(&claim).unwrap().applied().unwrap();
    let command = PublicationEffectCommand::dispatch("dispatch-1", &scope, context, &dispatch);
    let dispatch = ledger
        .dispatch_command(&command, dispatch)
        .unwrap()
        .applied()
        .unwrap();
    let command = PublicationEffectCommand::succeed(
        "succeed-1",
        &scope,
        &dispatch,
        Digest::fixture([42; 32]),
    );
    ledger.succeed_command(&command, dispatch).unwrap();

    drop(ledger);
    let mut reopened =
        crate::publication_effect_durable::DurableFixturePublicationEffectLedger::reopen(&path)
            .unwrap();
    assert_eq!(
        reopened.state("ns-1"),
        Some(PublicationEffectState::Succeeded)
    );
    assert_eq!(reopened.settlement("ns-1"), Some(Digest::fixture([42; 32])));
    // exact replay after reopen
    assert!(matches!(
        reopened.claim_command(&claim),
        Ok(crate::publication_effect_types::PublicationEffectExecution::Replayed(_))
    ));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn signed_settlement_verifies_against_exact_executor_key_and_rejects_forgery() {
    use crate::publication_effect_evidence::{PublicationSettlement, RawPublicationSettlement};
    use ed25519_dalek::SigningKey;

    let key = SigningKey::from_bytes(&[77; 32]);
    let other = SigningKey::from_bytes(&[88; 32]);
    let settlement = PublicationSettlement {
        schema_version: "runne.release.publication-effect-settlement/1".into(),
        idempotency_namespace: "ns-1".into(),
        generation: 1,
        destination_readback_sha256: "ab".repeat(32),
        executable_sha256: "cd".repeat(32),
        workflow_sha256: "ef".repeat(32),
        observed_result: "succeeded".into(),
    };

    let signed = RawPublicationSettlement::signed(&settlement, &key);
    let public = key.verifying_key().to_bytes();
    let (parsed, digest) = signed.verified(&public).unwrap();
    assert_eq!(parsed, settlement);
    assert_ne!(digest, Digest::fixture([0; 32]));

    // wrong executor key is rejected
    let signed = RawPublicationSettlement::signed(&settlement, &key);
    let other_public = other.verifying_key().to_bytes();
    assert_eq!(
        signed.verified(&other_public),
        Err(crate::publication_effect_types::PublicationEffectError::SettlementMismatch)
    );

    // tampered canonical bytes are rejected
    let mut signed = RawPublicationSettlement::signed(&settlement, &key);
    signed.raw[0] ^= 0x01;
    assert_eq!(
        signed.verified(&public),
        Err(crate::publication_effect_types::PublicationEffectError::SettlementMismatch)
    );
}

#[test]
fn rust_settlement_bytes_match_the_full_schema_golden() {
    use crate::publication_effect_evidence::{PublicationSettlement, RawPublicationSettlement};
    use ed25519_dalek::SigningKey;

    let settlement = PublicationSettlement {
        schema_version: "runne.release.publication-effect-settlement/1".into(),
        idempotency_namespace: "ns-1".into(),
        generation: 1,
        destination_readback_sha256: "ab".repeat(32),
        executable_sha256: "cd".repeat(32),
        workflow_sha256: "ef".repeat(32),
        observed_result: "succeeded".into(),
    };
    let raw = RawPublicationSettlement::signed(&settlement, &SigningKey::from_bytes(&[77; 32]));
    assert_eq!(
        raw.raw,
        include_bytes!("../tests/fixtures/publication_effect_settlement_v1.json")
    );
}

#[test]
fn rust_settlement_rejects_schema_invalid_signed_payloads() {
    use crate::publication_effect_evidence::{PublicationSettlement, RawPublicationSettlement};
    use ed25519_dalek::SigningKey;
    let key = SigningKey::from_bytes(&[77; 32]);
    let invalid = PublicationSettlement {
        schema_version: "runne.release.publication-effect-settlement/1".into(),
        idempotency_namespace: "bad value".into(),
        generation: 0,
        destination_readback_sha256: "A".repeat(64),
        executable_sha256: "cd".repeat(32),
        workflow_sha256: "ef".repeat(32),
        observed_result: "unknown".into(),
    };
    assert_eq!(
        RawPublicationSettlement::signed(&invalid, &key).verified(&key.verifying_key().to_bytes()),
        Err(PublicationEffectError::SettlementMismatch)
    );
}
