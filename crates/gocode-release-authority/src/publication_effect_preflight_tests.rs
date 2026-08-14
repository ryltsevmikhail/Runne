use crate::Digest;
use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_durable::encode_ledger;
use crate::publication_effect_ledger::FixturePublicationEffectLedger;
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectExecution,
    PublicationEffectScope, PublicationEffectState, ReconcileOutcome,
};

const CONTEXT: PublicationEffectContext = PublicationEffectContext {
    observed_at: 15,
    revocation_epoch: 1,
    allowlist_generation: 1,
};

fn scope(generation: u64) -> PublicationEffectScope {
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
        generation,
    }
}

fn mutations(original: &PublicationEffectScope) -> Vec<(&'static str, PublicationEffectScope)> {
    let mut cases = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut value = original.clone();
            value.$field = $value;
            cases.push((stringify!($field), value));
        }};
    }
    changed!(authority_instance, Digest::fixture([10; 32]));
    changed!(promotion, "promotion-b".into());
    changed!(candidate_digest, Digest::fixture([11; 32]));
    changed!(rc3_authorization_digest, Digest::fixture([12; 32]));
    changed!(manifest_digest, Digest::fixture([13; 32]));
    changed!(final_review_digest, Digest::fixture([14; 32]));
    changed!(allowlist_digest, Digest::fixture([15; 32]));
    changed!(allowlist_generation, 2);
    changed!(destination, "other".into());
    changed!(channel, "other".into());
    changed!(effect_kind, "other".into());
    changed!(effect_scope_digest, Digest::fixture([16; 32]));
    changed!(
        executor,
        [
            "other".into(),
            "account".into(),
            "lane".into(),
            "key".into(),
            "profile".into()
        ]
    );
    changed!(executable_digest, Digest::fixture([17; 32]));
    changed!(workflow_digest, Digest::fixture([18; 32]));
    changed!(idempotency_namespace, "other".into());
    changed!(valid_from, 11);
    changed!(expires_at, 19);
    changed!(revocation_epoch, 2);
    changed!(generation, original.generation + 1);
    cases
}

fn applied(value: PublicationEffectExecution) -> FixturePublicationDispatch {
    value.applied().unwrap()
}

fn claimed() -> (
    FixturePublicationEffectLedger,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let mut ledger = FixturePublicationEffectLedger::default();
    let scope = scope(1);
    let command = PublicationEffectCommand::claim("claim-1", &scope, CONTEXT);
    let capability = applied(ledger.claim_command(&command).unwrap());
    (ledger, scope, capability)
}

fn in_flight() -> (
    FixturePublicationEffectLedger,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let (mut ledger, scope, capability) = claimed();
    let command = PublicationEffectCommand::dispatch("dispatch-1", &scope, CONTEXT, &capability);
    let capability = applied(ledger.dispatch_command(&command, capability).unwrap());
    (ledger, scope, capability)
}

fn uncertain() -> (
    FixturePublicationEffectLedger,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let (mut ledger, scope, capability) = in_flight();
    let command = PublicationEffectCommand::mark_uncertain("uncertain-1", &scope, &capability);
    let capability = applied(ledger.mark_uncertain_command(&command, capability).unwrap());
    (ledger, scope, capability)
}

fn absent() -> (
    FixturePublicationEffectLedger,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let (mut ledger, scope, capability) = uncertain();
    let command = PublicationEffectCommand::reconcile(
        "reconcile-1",
        &scope,
        &capability,
        ReconcileOutcome::Absent,
        Digest::fixture([21; 32]),
    );
    let capability = applied(ledger.reconcile_command(&command, capability).unwrap());
    (ledger, scope, capability)
}

fn unchanged(
    ledger: &FixturePublicationEffectLedger,
    before: &[u8],
    state: PublicationEffectState,
) {
    assert_eq!(ledger.state("ns-1"), Some(state));
    assert_eq!(encode_ledger(ledger).unwrap(), before);
}

#[test]
fn every_operation_rejects_each_scope_mutation_before_in_memory_state_changes() {
    for (field, changed) in mutations(&scope(1)) {
        let (mut ledger, _, capability) = claimed();
        let before = encode_ledger(&ledger).unwrap();
        let command =
            PublicationEffectCommand::dispatch("dispatch-new", &changed, CONTEXT, &capability);
        assert_eq!(
            ledger.dispatch_command(&command, capability),
            Err(PublicationEffectError::DivergentClaim),
            "dispatch {field}"
        );
        unchanged(&ledger, &before, PublicationEffectState::Claimed);

        let (mut ledger, _, capability) = in_flight();
        let before = encode_ledger(&ledger).unwrap();
        let command =
            PublicationEffectCommand::mark_uncertain("uncertain-new", &changed, &capability);
        assert_eq!(
            ledger.mark_uncertain_command(&command, capability),
            Err(PublicationEffectError::DivergentClaim),
            "mark {field}"
        );
        unchanged(&ledger, &before, PublicationEffectState::InFlight);

        let (mut ledger, _, capability) = in_flight();
        let before = encode_ledger(&ledger).unwrap();
        let command = PublicationEffectCommand::succeed(
            "succeed-new",
            &changed,
            &capability,
            Digest::fixture([22; 32]),
        );
        assert_eq!(
            ledger.succeed_command(&command, capability),
            Err(PublicationEffectError::DivergentClaim),
            "succeed {field}"
        );
        unchanged(&ledger, &before, PublicationEffectState::InFlight);

        let (mut ledger, _, capability) = uncertain();
        let before = encode_ledger(&ledger).unwrap();
        let command = PublicationEffectCommand::reconcile(
            "reconcile-new",
            &changed,
            &capability,
            ReconcileOutcome::Succeeded,
            Digest::fixture([23; 32]),
        );
        assert_eq!(
            ledger.reconcile_command(&command, capability),
            Err(PublicationEffectError::DivergentClaim),
            "reconcile {field}"
        );
        unchanged(&ledger, &before, PublicationEffectState::Uncertain);
    }

    for (field, changed) in mutations(&scope(2)) {
        let (mut ledger, _, capability) = absent();
        let before = encode_ledger(&ledger).unwrap();
        let command =
            PublicationEffectCommand::reclaim("reclaim-new", &changed, CONTEXT, &capability);
        assert_eq!(
            ledger.reclaim_command(&command, capability),
            Err(PublicationEffectError::DivergentClaim),
            "reclaim {field}"
        );
        unchanged(&ledger, &before, PublicationEffectState::ReconciledAbsent);
    }
}

#[test]
fn invalid_command_ids_fail_before_every_transition_and_leave_exact_bytes() {
    let mut ledger = FixturePublicationEffectLedger::default();
    let original = scope(1);
    let command = PublicationEffectCommand::claim("bad id", &original, CONTEXT);
    assert_eq!(
        ledger.claim_command(&command),
        Err(PublicationEffectError::InvalidAuthorization)
    );
    assert!(ledger.is_empty());

    let (mut ledger, scope, capability) = claimed();
    let before = encode_ledger(&ledger).unwrap();
    let command = PublicationEffectCommand::dispatch("bad id", &scope, CONTEXT, &capability);
    assert_eq!(
        ledger.dispatch_command(&command, capability),
        Err(PublicationEffectError::InvalidAuthorization)
    );
    unchanged(&ledger, &before, PublicationEffectState::Claimed);

    let (mut ledger, scope, capability) = in_flight();
    let before = encode_ledger(&ledger).unwrap();
    let command = PublicationEffectCommand::mark_uncertain("bad id", &scope, &capability);
    assert_eq!(
        ledger.mark_uncertain_command(&command, capability),
        Err(PublicationEffectError::InvalidAuthorization)
    );
    unchanged(&ledger, &before, PublicationEffectState::InFlight);

    let (mut ledger, scope, capability) = in_flight();
    let before = encode_ledger(&ledger).unwrap();
    let command =
        PublicationEffectCommand::succeed("bad id", &scope, &capability, Digest::fixture([22; 32]));
    assert_eq!(
        ledger.succeed_command(&command, capability),
        Err(PublicationEffectError::InvalidAuthorization)
    );
    unchanged(&ledger, &before, PublicationEffectState::InFlight);

    let (mut ledger, scope, capability) = uncertain();
    let before = encode_ledger(&ledger).unwrap();
    let command = PublicationEffectCommand::reconcile(
        "bad id",
        &scope,
        &capability,
        ReconcileOutcome::Absent,
        Digest::fixture([23; 32]),
    );
    assert_eq!(
        ledger.reconcile_command(&command, capability),
        Err(PublicationEffectError::InvalidAuthorization)
    );
    unchanged(&ledger, &before, PublicationEffectState::Uncertain);

    let (mut ledger, _, capability) = absent();
    let next = self::scope(2);
    let before = encode_ledger(&ledger).unwrap();
    let command = PublicationEffectCommand::reclaim("bad id", &next, CONTEXT, &capability);
    assert_eq!(
        ledger.reclaim_command(&command, capability),
        Err(PublicationEffectError::InvalidAuthorization)
    );
    unchanged(&ledger, &before, PublicationEffectState::ReconciledAbsent);
}
