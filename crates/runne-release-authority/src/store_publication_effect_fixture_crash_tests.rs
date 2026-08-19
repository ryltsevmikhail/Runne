use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_failpoint::PublicationEffectFailpoint;
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectExecution,
    PublicationEffectScope, PublicationEffectState, ReconcileOutcome,
};
use crate::{Digest, DurableFixturePromotionAuthority};

use crate::store_publication_effect_fixture_tests::{binding, fixture};

const CONTEXT: PublicationEffectContext = PublicationEffectContext {
    observed_at: 15,
    revocation_epoch: 1,
    allowlist_generation: 1,
};

fn path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "runne-authority-publication-cut-{name}-{}",
        std::process::id()
    ))
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
}

fn root(
    name: &str,
) -> (
    std::path::PathBuf,
    DurableFixturePromotionAuthority,
    PublicationEffectScope,
) {
    let path = path(name);
    cleanup(&path);
    let (memory, scope) = fixture();
    let authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    (path, authority, scope)
}

fn applied(value: PublicationEffectExecution) -> FixturePublicationDispatch {
    value.applied().unwrap()
}

fn claimed(
    name: &str,
) -> (
    std::path::PathBuf,
    DurableFixturePromotionAuthority,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let (path, authority, scope) = root(name);
    let command = PublicationEffectCommand::claim("claim-1", &scope, CONTEXT);
    let capability = applied(
        authority
            .fixture_claim_publication_command(&command)
            .unwrap(),
    );
    (path, authority, scope, capability)
}

fn in_flight(
    name: &str,
) -> (
    std::path::PathBuf,
    DurableFixturePromotionAuthority,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let (path, authority, scope, capability) = claimed(name);
    let command = PublicationEffectCommand::dispatch("dispatch-1", &scope, CONTEXT, &capability);
    let capability = applied(
        authority
            .fixture_dispatch_publication_command(&command, capability)
            .unwrap(),
    );
    (path, authority, scope, capability)
}

fn uncertain(
    name: &str,
) -> (
    std::path::PathBuf,
    DurableFixturePromotionAuthority,
    PublicationEffectScope,
    FixturePublicationDispatch,
) {
    let (path, authority, scope, capability) = in_flight(name);
    let command = PublicationEffectCommand::mark_uncertain("uncertain-1", &scope, &capability);
    let capability = applied(
        authority
            .fixture_mark_uncertain_publication_command(&command, capability)
            .unwrap(),
    );
    (path, authority, scope, capability)
}

#[test]
fn authoritative_claim_and_dispatch_cuts_reopen_without_a_second_live_dispatch() {
    let (path, authority, scope) = root("claim-cuts");
    let claim = PublicationEffectCommand::claim("claim-1", &scope, CONTEXT);
    authority.arm_publication_failpoint(PublicationEffectFailpoint::BeforeClaimSave);
    assert_eq!(
        authority.fixture_claim_publication_command(&claim),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    assert_eq!(
        authority.fixture_replay_publication_command(&claim),
        Err(PublicationEffectError::InvalidState)
    );
    authority.arm_publication_failpoint(PublicationEffectFailpoint::AfterClaimSave);
    assert_eq!(
        authority.fixture_claim_publication_command(&claim),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(authority);
    let authority = DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap();
    assert_eq!(
        authority
            .fixture_replay_publication_command(&claim)
            .unwrap()
            .state,
        PublicationEffectState::Claimed
    );
    assert!(matches!(
        authority.fixture_claim_publication_command(&claim).unwrap(),
        PublicationEffectExecution::Replayed(_)
    ));
    drop(authority);
    cleanup(&path);

    let (path, authority, scope, capability) = claimed("dispatch-cut");
    let dispatch = PublicationEffectCommand::dispatch("dispatch-1", &scope, CONTEXT, &capability);
    authority.arm_publication_failpoint(PublicationEffectFailpoint::AfterInFlightSave);
    assert_eq!(
        authority.fixture_dispatch_publication_command(&dispatch, capability),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(authority);
    let authority = DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap();
    assert_eq!(
        authority
            .fixture_replay_publication_command(&dispatch)
            .unwrap()
            .state,
        PublicationEffectState::InFlight
    );
    authority
        .fixture_mark_response_lost("uncertain-1", &scope)
        .unwrap();
    drop(authority);
    cleanup(&path);
}

#[test]
fn authoritative_settlement_cuts_persist_exact_replay() {
    for (cut, expected, name) in [
        (
            PublicationEffectFailpoint::BeforeSettlementSave,
            PublicationEffectState::InFlight,
            "settle-before",
        ),
        (
            PublicationEffectFailpoint::AfterSettlementSave,
            PublicationEffectState::Succeeded,
            "settle-after",
        ),
    ] {
        let (path, authority, scope, capability) = in_flight(name);
        let settle = PublicationEffectCommand::succeed(
            "settle-1",
            &scope,
            &capability,
            Digest::fixture([42; 32]),
        );
        authority.arm_publication_failpoint(cut);
        assert_eq!(
            authority.fixture_succeed_publication_command(&settle, capability),
            Err(PublicationEffectError::DurableStateUnavailable)
        );
        drop(authority);
        let authority = DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap();
        if expected == PublicationEffectState::Succeeded {
            assert_eq!(
                authority
                    .fixture_replay_publication_command(&settle)
                    .unwrap()
                    .evidence,
                Some(Digest::fixture([42; 32]))
            );
        } else {
            authority
                .fixture_mark_response_lost("response-lost-1", &scope)
                .unwrap();
        }
        drop(authority);
        cleanup(&path);
    }
}

#[test]
fn authoritative_uncertain_and_reconcile_cuts_persist_exact_replay() {
    let (path, authority, scope, capability) = in_flight("uncertain-cut");
    let command = PublicationEffectCommand::mark_uncertain("uncertain-1", &scope, &capability);
    authority.arm_publication_failpoint(PublicationEffectFailpoint::AfterUncertainSave);
    assert_eq!(
        authority.fixture_mark_uncertain_publication_command(&command, capability),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(authority);
    let authority = DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap();
    assert_eq!(
        authority
            .fixture_replay_publication_command(&command)
            .unwrap()
            .state,
        PublicationEffectState::Uncertain
    );
    drop(authority);
    cleanup(&path);

    for (result, expected, name) in [
        (
            ReconcileOutcome::Succeeded,
            PublicationEffectState::ReconciledSucceeded,
            "reconcile-succeeded",
        ),
        (
            ReconcileOutcome::Absent,
            PublicationEffectState::ReconciledAbsent,
            "reconcile-absent",
        ),
        (
            ReconcileOutcome::Inconclusive,
            PublicationEffectState::Blocked,
            "reconcile-blocked",
        ),
    ] {
        let (path, authority, scope, capability) = uncertain(name);
        let command = PublicationEffectCommand::reconcile(
            "reconcile-1",
            &scope,
            &capability,
            result,
            Digest::fixture([55; 32]),
        );
        authority.arm_publication_failpoint(PublicationEffectFailpoint::AfterReconcileSave);
        assert_eq!(
            authority.fixture_reconcile_publication_command(&command, capability),
            Err(PublicationEffectError::DurableStateUnavailable)
        );
        drop(authority);
        let authority = DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap();
        let replay = authority
            .fixture_replay_publication_command(&command)
            .unwrap();
        assert_eq!(
            (replay.state, replay.evidence),
            (expected, Some(Digest::fixture([55; 32])))
        );
        let mut next = scope.clone();
        next.generation = 2;
        let result = authority.fixture_reclaim_after_absence("reclaim-1", &next, CONTEXT);
        assert_eq!(
            result.is_ok(),
            expected == PublicationEffectState::ReconciledAbsent
        );
        assert!(
            authority
                .fixture_reclaim_after_absence("reclaim-1", &next, CONTEXT)
                .is_err()
        );
        drop(authority);
        cleanup(&path);
    }
}
