use crate::Digest;
use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_ledger::FixturePublicationEffectLedger;
use crate::publication_effect_types::{
    PublicationEffectError, PublicationEffectScope, PublicationEffectState, ReconcileOutcome,
};

fn scope() -> PublicationEffectScope {
    PublicationEffectScope {
        authority_instance: Digest::fixture([1; 32]),
        promotion: "promotion-a".into(),
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
        idempotency_namespace: "ns-1".into(),
        valid_from: 10,
        expires_at: 20,
        revocation_epoch: 1,
        generation: 1,
    }
}

const CONTEXT: PublicationEffectContext = PublicationEffectContext {
    observed_at: 15,
    revocation_epoch: 1,
    allowlist_generation: 1,
};

fn command_claim(ledger: &mut FixturePublicationEffectLedger, scope: &PublicationEffectScope) {
    ledger
        .claim_command(&PublicationEffectCommand::claim("claim-1", scope, CONTEXT))
        .unwrap()
        .applied()
        .unwrap();
}

#[test]
fn reclaim_rejects_mutation_of_every_frozen_scope_field() {
    macro_rules! assert_frozen {
        ($field:ident = $value:expr) => {{
            let mut ledger = FixturePublicationEffectLedger::default();
            let scope = scope();
            let dispatch = ledger.claim(&scope, 15, 1, 1).unwrap();
            let dispatch = ledger.dispatch(dispatch, 15, 1, 1).unwrap();
            let dispatch = ledger.mark_uncertain(dispatch).unwrap();
            let dispatch = ledger
                .reconcile(dispatch, ReconcileOutcome::Absent, Digest::fixture([0; 32]))
                .unwrap();
            let mut replacement = scope.clone();
            replacement.generation = 2;
            replacement.$field = $value;
            assert_eq!(
                ledger.reclaim(dispatch, &replacement, 15, 1, 1),
                Err(PublicationEffectError::DivergentClaim),
                stringify!($field)
            );
        }};
    }
    assert_frozen!(authority_instance = Digest::fixture([10; 32]));
    assert_frozen!(promotion = "promotion-b".into());
    assert_frozen!(candidate_digest = Digest::fixture([11; 32]));
    assert_frozen!(rc3_authorization_digest = Digest::fixture([12; 32]));
    assert_frozen!(manifest_digest = Digest::fixture([13; 32]));
    assert_frozen!(final_review_digest = Digest::fixture([14; 32]));
    assert_frozen!(allowlist_digest = Digest::fixture([15; 32]));
    assert_frozen!(allowlist_generation = 2);
    assert_frozen!(destination = "other".into());
    assert_frozen!(channel = "other".into());
    assert_frozen!(effect_kind = "other".into());
    assert_frozen!(effect_scope_digest = Digest::fixture([16; 32]));
    assert_frozen!(
        executor = [
            "other".into(),
            "account".into(),
            "lane".into(),
            "key".into(),
            "profile".into()
        ]
    );
    assert_frozen!(executable_digest = Digest::fixture([17; 32]));
    assert_frozen!(workflow_digest = Digest::fixture([18; 32]));
    assert_frozen!(idempotency_namespace = "other".into());
    assert_frozen!(valid_from = 11);
    assert_frozen!(expires_at = 19);
    assert_frozen!(revocation_epoch = 2);
}

#[test]
fn durable_decode_rejects_outer_namespace_substitution() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let scope = scope();
    command_claim(&mut ledger, &scope);
    let bytes = crate::publication_effect_durable::encode_ledger(&ledger).unwrap();
    let bytes = String::from_utf8(bytes).unwrap().replace(
        "\"idempotency_namespace\":\"ns-1\"",
        "\"idempotency_namespace\":\"ns-2\"",
    );
    assert!(matches!(
        crate::publication_effect_durable::decode_ledger(bytes.as_bytes()),
        Err(PublicationEffectError::DurableStateUnavailable)
    ));
}

#[test]
fn durable_encode_rejects_invalid_in_memory_claims_before_save() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let expected = scope();
    command_claim(&mut ledger, &expected);
    ledger
        .bindings
        .get_mut("ns-1")
        .unwrap()
        .scope
        .idempotency_namespace = "ns-2".into();
    assert!(matches!(
        crate::publication_effect_durable::encode_ledger(&ledger),
        Err(PublicationEffectError::DurableStateUnavailable)
    ));
}

#[test]
fn exact_claim_replay_is_a_receipt_without_a_dispatch_capability() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let scope = scope();
    ledger
        .claim_command(&PublicationEffectCommand::claim("claim-1", &scope, CONTEXT))
        .unwrap()
        .applied()
        .unwrap();
    let replay = ledger
        .claim_command(&PublicationEffectCommand::claim("claim-1", &scope, CONTEXT))
        .unwrap();
    assert!(matches!(
        replay,
        crate::publication_effect_types::PublicationEffectExecution::Replayed(_)
    ));
    assert_eq!(ledger.state("ns-1"), Some(PublicationEffectState::Claimed));
}

#[test]
fn raw_in_memory_recovery_returns_only_a_non_dispatchable_snapshot() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let expected = scope();
    ledger.claim(&expected, 15, 1, 1).unwrap();
    let recovered = ledger.recover(&expected).unwrap();
    assert_eq!(recovered.state, PublicationEffectState::Claimed);
    assert_eq!(recovered.generation, 1);
    assert_eq!(recovered.settlement, None);
    assert_eq!(ledger.state("ns-1"), Some(PublicationEffectState::Claimed));
}

#[test]
fn durable_recovery_after_reopen_returns_only_a_snapshot() {
    let path = std::env::temp_dir().join(format!(
        "publication-effect-raw-recovery-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let expected = scope();
    let mut ledger =
        crate::publication_effect_durable::DurableFixturePublicationEffectLedger::create(&path)
            .unwrap();
    let command = PublicationEffectCommand::claim("claim-1", &expected, CONTEXT);
    let _first_capability = ledger.claim_command(&command).unwrap().applied().unwrap();
    drop(ledger);
    let ledger =
        crate::publication_effect_durable::DurableFixturePublicationEffectLedger::reopen(&path)
            .unwrap();
    let before = std::fs::read(&path).unwrap();
    let recovered = ledger.recover(&expected).unwrap();
    assert_eq!(recovered.state, PublicationEffectState::Claimed);
    assert_eq!(recovered.generation, 1);
    assert_eq!(recovered.settlement, None);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn exact_claim_replay_after_reopen_returns_stored_outcome_without_mutation() {
    let path = std::env::temp_dir().join(format!(
        "publication-effect-claim-replay-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let expected_scope = scope();
    let mut ledger =
        crate::publication_effect_durable::DurableFixturePublicationEffectLedger::create(&path)
            .unwrap();
    let command = PublicationEffectCommand::claim("claim-1", &expected_scope, CONTEXT);
    ledger.claim_command(&command).unwrap().applied().unwrap();
    drop(ledger);

    let before = std::fs::read(&path).unwrap();
    let mut reopened =
        crate::publication_effect_durable::DurableFixturePublicationEffectLedger::reopen(&path)
            .unwrap();
    assert!(matches!(
        reopened.claim_command(&command),
        Ok(crate::publication_effect_types::PublicationEffectExecution::Replayed(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let _ = std::fs::remove_file(&path);
}

#[cfg(unix)]
#[test]
fn failed_durable_save_does_not_publish_mutated_memory() {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!(
        "publication-effect-save-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let mut ledger =
        crate::publication_effect_durable::DurableFixturePublicationEffectLedger::create(&path)
            .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        ledger.claim_command(&PublicationEffectCommand::claim(
            "claim-1",
            &scope(),
            CONTEXT
        )),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    assert_eq!(ledger.state("ns-1"), None);
    let _ = std::fs::remove_file(&path);
}
