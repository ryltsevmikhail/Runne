use crate::Digest;
use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_durable::DurableFixturePublicationEffectLedger;
use crate::publication_effect_failpoint::PublicationEffectFailpoint;
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectExecution,
    PublicationEffectScope, PublicationEffectState, ReconcileOutcome,
};

const CONTEXT: PublicationEffectContext = PublicationEffectContext {
    observed_at: 15,
    revocation_epoch: 1,
    allowlist_generation: 1,
};

fn scope(namespace: &str) -> PublicationEffectScope {
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
        idempotency_namespace: namespace.into(),
        valid_from: 10,
        expires_at: 20,
        revocation_epoch: 1,
        generation: 1,
    }
}

fn path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "publication-effect-crash-{name}-{}",
        std::process::id()
    ))
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let lease = path.with_extension(
        path.extension()
            .and_then(|value| value.to_str())
            .map_or_else(|| "lease".into(), |value| format!("{value}.lease")),
    );
    let _ = std::fs::remove_file(lease);
}

fn applied(value: PublicationEffectExecution) -> FixturePublicationDispatch {
    value.applied().unwrap()
}

fn claimed(
    path: &std::path::Path,
) -> (
    DurableFixturePublicationEffectLedger,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    cleanup(path);
    let scope = scope("ns-1");
    let mut ledger = DurableFixturePublicationEffectLedger::create(path).unwrap();
    let capability = applied(
        ledger
            .claim_command(&PublicationEffectCommand::claim(
                "claim-1", &scope, CONTEXT,
            ))
            .unwrap(),
    );
    (ledger, scope, capability)
}

fn in_flight(
    path: &std::path::Path,
) -> (
    DurableFixturePublicationEffectLedger,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let (mut ledger, scope, capability) = claimed(path);
    let command = PublicationEffectCommand::dispatch("dispatch-1", &scope, CONTEXT, &capability);
    let capability = applied(ledger.dispatch_command(&command, capability).unwrap());
    (ledger, scope, capability)
}

fn uncertain(
    path: &std::path::Path,
) -> (
    DurableFixturePublicationEffectLedger,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let (mut ledger, scope, capability) = in_flight(path);
    let command = PublicationEffectCommand::mark_uncertain("uncertain-1", &scope, &capability);
    let capability = applied(
        ledger
            .mark_uncertain_command(&command, capability)
            .unwrap(),
    );
    (ledger, scope, capability)
}

#[test]
fn post_rename_failure_poison_fences_stale_memory_until_reopen() {
    let path = path("rename-parent-sync");
    cleanup(&path);
    let mut ledger = DurableFixturePublicationEffectLedger::create(&path).unwrap();
    ledger.arm_failpoint(PublicationEffectFailpoint::AfterRenameBeforeParentSync);
    let first = scope("ns-1");
    assert_eq!(
        ledger.claim_command(&PublicationEffectCommand::claim("claim-1", &first, CONTEXT)),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    let second = scope("ns-2");
    assert_eq!(
        ledger.claim_command(&PublicationEffectCommand::claim("claim-2", &second, CONTEXT)),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(ledger);

    let reopened = DurableFixturePublicationEffectLedger::reopen(&path).unwrap();
    assert_eq!(reopened.state("ns-1"), Some(PublicationEffectState::Claimed));
    assert_eq!(reopened.state("ns-2"), None);
    cleanup(&path);
}

#[test]
fn claim_crash_cuts_preserve_none_or_exact_replay_without_a_second_capability() {
    let before = path("before-claim-save");
    cleanup(&before);
    let scope = scope("ns-1");
    let command = PublicationEffectCommand::claim("claim-1", &scope, CONTEXT);
    let mut ledger = DurableFixturePublicationEffectLedger::create(&before).unwrap();
    ledger.arm_failpoint(PublicationEffectFailpoint::BeforeClaimSave);
    assert_eq!(
        ledger.claim_command(&command),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(ledger);
    let reopened = DurableFixturePublicationEffectLedger::reopen(&before).unwrap();
    assert_eq!(reopened.state("ns-1"), None);
    cleanup(&before);

    let after = path("after-claim-save");
    cleanup(&after);
    let mut ledger = DurableFixturePublicationEffectLedger::create(&after).unwrap();
    ledger.arm_failpoint(PublicationEffectFailpoint::AfterClaimSave);
    assert_eq!(
        ledger.claim_command(&command),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(ledger);
    let mut reopened = DurableFixturePublicationEffectLedger::reopen(&after).unwrap();
    assert_eq!(
        reopened.replay_command(&command).unwrap().state,
        PublicationEffectState::Claimed
    );
    assert!(matches!(
        reopened.claim_command(&command),
        Ok(PublicationEffectExecution::Replayed(_))
    ));
    cleanup(&after);
}

#[test]
fn dispatch_and_settlement_crash_cuts_never_falsely_succeed_or_redispatch() {
    let dispatch_path = path("after-in-flight-save");
    let (mut ledger, scope, capability) = claimed(&dispatch_path);
    let dispatch = PublicationEffectCommand::dispatch("dispatch-1", &scope, CONTEXT, &capability);
    ledger.arm_failpoint(PublicationEffectFailpoint::AfterInFlightSave);
    assert_eq!(
        ledger.dispatch_command(&dispatch, capability),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(ledger);
    let mut reopened = DurableFixturePublicationEffectLedger::reopen(&dispatch_path).unwrap();
    assert_eq!(reopened.state("ns-1"), Some(PublicationEffectState::InFlight));
    assert_eq!(
        reopened.replay_command(&dispatch).unwrap().state,
        PublicationEffectState::InFlight
    );
    reopened.mark_response_lost("uncertain-1", &scope).unwrap();
    assert_eq!(reopened.state("ns-1"), Some(PublicationEffectState::Uncertain));
    cleanup(&dispatch_path);

    let before = path("before-settlement-save");
    let (mut ledger, scope, capability) = in_flight(&before);
    let settle = PublicationEffectCommand::succeed(
        "settle-1",
        &scope,
        &capability,
        Digest::fixture([42; 32]),
    );
    ledger.arm_failpoint(PublicationEffectFailpoint::BeforeSettlementSave);
    assert_eq!(
        ledger.succeed_command(&settle, capability),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(ledger);
    let mut reopened = DurableFixturePublicationEffectLedger::reopen(&before).unwrap();
    assert_eq!(reopened.state("ns-1"), Some(PublicationEffectState::InFlight));
    reopened.mark_response_lost("response-lost-1", &scope).unwrap();
    cleanup(&before);

    let after = path("after-settlement-save");
    let (mut ledger, scope, capability) = in_flight(&after);
    let settle = PublicationEffectCommand::succeed(
        "settle-1",
        &scope,
        &capability,
        Digest::fixture([42; 32]),
    );
    ledger.arm_failpoint(PublicationEffectFailpoint::AfterSettlementSave);
    assert_eq!(
        ledger.succeed_command(&settle, capability),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(ledger);
    let reopened = DurableFixturePublicationEffectLedger::reopen(&after).unwrap();
    assert_eq!(reopened.state("ns-1"), Some(PublicationEffectState::Succeeded));
    assert_eq!(reopened.replay_command(&settle).unwrap().evidence, Some(Digest::fixture([42; 32])));
    cleanup(&after);
}

#[test]
fn uncertain_and_each_reconcile_result_survive_response_loss_exactly() {
    let uncertain_path = path("after-uncertain-save");
    let (mut ledger, scope, capability) = in_flight(&uncertain_path);
    let command = PublicationEffectCommand::mark_uncertain("uncertain-1", &scope, &capability);
    ledger.arm_failpoint(PublicationEffectFailpoint::AfterUncertainSave);
    assert_eq!(
        ledger.mark_uncertain_command(&command, capability),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(ledger);
    let reopened = DurableFixturePublicationEffectLedger::reopen(&uncertain_path).unwrap();
    assert_eq!(reopened.state("ns-1"), Some(PublicationEffectState::Uncertain));
    cleanup(&uncertain_path);

    for (result, expected, suffix) in [
        (ReconcileOutcome::Succeeded, PublicationEffectState::ReconciledSucceeded, "succeeded"),
        (ReconcileOutcome::Absent, PublicationEffectState::ReconciledAbsent, "absent"),
        (ReconcileOutcome::Inconclusive, PublicationEffectState::Blocked, "blocked"),
    ] {
        let path = path(suffix);
        let (mut ledger, scope, capability) = uncertain(&path);
        let evidence = Digest::fixture([55; 32]);
        let command = PublicationEffectCommand::reconcile(
            "reconcile-1", &scope, &capability, result, evidence,
        );
        ledger.arm_failpoint(PublicationEffectFailpoint::AfterReconcileSave);
        assert_eq!(
            ledger.reconcile_command(&command, capability),
            Err(PublicationEffectError::DurableStateUnavailable)
        );
        drop(ledger);
        let mut reopened = DurableFixturePublicationEffectLedger::reopen(&path).unwrap();
        assert_eq!(reopened.state("ns-1"), Some(expected));
        assert_eq!(reopened.replay_command(&command).unwrap().evidence, Some(evidence));
        let mut next = scope.clone();
        next.generation = 2;
        if result == ReconcileOutcome::Absent {
            assert!(matches!(
                reopened.reclaim_after_absence("reclaim-1", &next, CONTEXT),
                Ok(PublicationEffectExecution::Applied(_))
            ));
        }
        assert_eq!(
            reopened.reclaim_after_absence("reclaim-1", &next, CONTEXT),
            Err(PublicationEffectError::InvalidState)
        );
        cleanup(&path);
    }
}
