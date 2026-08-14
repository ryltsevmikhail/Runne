use crate::Digest;
use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_durable::DurableFixturePublicationEffectLedger;
use crate::publication_effect_types::{
    PublicationEffectError, PublicationEffectExecution, PublicationEffectScope,
    PublicationEffectState, ReconcileOutcome,
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
fn path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "publication-effect-{name}-{}.json",
        std::process::id()
    ))
}
fn applied(
    value: PublicationEffectExecution,
) -> crate::publication_effect_types::FixturePublicationDispatch {
    value.applied().unwrap()
}

#[test]
fn every_success_operation_replays_its_original_outcome_after_reopen() {
    let path = path("success-replay");
    let _ = std::fs::remove_file(&path);
    let scope = scope(1);
    let mut ledger = DurableFixturePublicationEffectLedger::create(&path).unwrap();
    let claim = PublicationEffectCommand::claim("claim-1", &scope, CONTEXT);
    let capability = applied(ledger.claim_command(&claim).unwrap());
    let dispatch = PublicationEffectCommand::dispatch("dispatch-1", &scope, CONTEXT, &capability);
    let capability = applied(ledger.dispatch_command(&dispatch, capability).unwrap());
    let succeed = PublicationEffectCommand::succeed(
        "succeed-1",
        &scope,
        &capability,
        Digest::fixture([42; 32]),
    );
    ledger.succeed_command(&succeed, capability).unwrap();
    drop(ledger);
    let ledger = DurableFixturePublicationEffectLedger::reopen(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    for (command, state, evidence) in [
        (&claim, PublicationEffectState::Claimed, None),
        (&dispatch, PublicationEffectState::InFlight, None),
        (
            &succeed,
            PublicationEffectState::Succeeded,
            Some(Digest::fixture([42; 32])),
        ),
    ] {
        let replay = ledger.replay_command(command).unwrap();
        assert_eq!(replay.state, state);
        assert_eq!(replay.evidence, evidence);
        assert_eq!(replay.command_fingerprint, command.fingerprint().unwrap());
    }
    let mut changed = dispatch.clone();
    if let PublicationEffectCommand::Dispatch { context, .. } = &mut changed {
        context.observed_at = 16;
    }
    assert_eq!(
        ledger.replay_command(&changed),
        Err(PublicationEffectError::CommandReplayDiverged)
    );
    let mut changed = dispatch.clone();
    if let PublicationEffectCommand::Dispatch { capability, .. } = &mut changed {
        *capability = Digest::fixture([90; 32]);
    }
    assert_eq!(
        ledger.replay_command(&changed),
        Err(PublicationEffectError::CommandReplayDiverged)
    );
    let mut changed = succeed.clone();
    if let PublicationEffectCommand::SucceedSettlement { evidence, .. } = &mut changed {
        *evidence = Digest::fixture([91; 32]);
    }
    assert_eq!(
        ledger.replay_command(&changed),
        Err(PublicationEffectError::CommandReplayDiverged)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn uncertain_absent_and_reclaim_operations_replay_after_reopen() {
    let path = path("absent-replay");
    let _ = std::fs::remove_file(&path);
    let first = scope(1);
    let next = scope(2);
    let mut ledger = DurableFixturePublicationEffectLedger::create(&path).unwrap();
    let claim = PublicationEffectCommand::claim("claim-1", &first, CONTEXT);
    let capability = applied(ledger.claim_command(&claim).unwrap());
    let dispatch = PublicationEffectCommand::dispatch("dispatch-1", &first, CONTEXT, &capability);
    let capability = applied(ledger.dispatch_command(&dispatch, capability).unwrap());
    let uncertain = PublicationEffectCommand::mark_uncertain("uncertain-1", &first, &capability);
    let capability = applied(
        ledger
            .mark_uncertain_command(&uncertain, capability)
            .unwrap(),
    );
    let reconcile = PublicationEffectCommand::reconcile(
        "reconcile-1",
        &first,
        &capability,
        ReconcileOutcome::Absent,
        Digest::fixture([43; 32]),
    );
    let capability = applied(ledger.reconcile_command(&reconcile, capability).unwrap());
    let reclaim = PublicationEffectCommand::reclaim("reclaim-1", &next, CONTEXT, &capability);
    ledger.reclaim_command(&reclaim, capability).unwrap();
    drop(ledger);
    let ledger = DurableFixturePublicationEffectLedger::reopen(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    for (command, state) in [
        (&uncertain, PublicationEffectState::Uncertain),
        (&reconcile, PublicationEffectState::ReconciledAbsent),
        (&reclaim, PublicationEffectState::Claimed),
    ] {
        assert_eq!(ledger.replay_command(command).unwrap().state, state);
    }
    let mut changed = uncertain.clone();
    if let PublicationEffectCommand::MarkUncertain { capability, .. } = &mut changed {
        *capability = Digest::fixture([90; 32]);
    }
    assert_eq!(
        ledger.replay_command(&changed),
        Err(PublicationEffectError::CommandReplayDiverged)
    );
    let mut changed = reconcile.clone();
    if let PublicationEffectCommand::Reconcile { result, .. } = &mut changed {
        *result = ReconcileOutcome::Succeeded;
    }
    assert_eq!(
        ledger.replay_command(&changed),
        Err(PublicationEffectError::CommandReplayDiverged)
    );
    let mut changed = reconcile.clone();
    if let PublicationEffectCommand::Reconcile { evidence, .. } = &mut changed {
        *evidence = Digest::fixture([91; 32]);
    }
    assert_eq!(
        ledger.replay_command(&changed),
        Err(PublicationEffectError::CommandReplayDiverged)
    );
    let mut changed = reclaim.clone();
    if let PublicationEffectCommand::Reclaim { context, .. } = &mut changed {
        context.allowlist_generation = 2;
    }
    assert_eq!(
        ledger.replay_command(&changed),
        Err(PublicationEffectError::CommandReplayDiverged)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let _ = std::fs::remove_file(&path);
}

fn reconcile_replay(result: ReconcileOutcome, want: PublicationEffectState, name: &str) {
    let path = path(name);
    let _ = std::fs::remove_file(&path);
    let scope = scope(1);
    let mut ledger = DurableFixturePublicationEffectLedger::create(&path).unwrap();
    let claim = PublicationEffectCommand::claim("claim-1", &scope, CONTEXT);
    let capability = applied(ledger.claim_command(&claim).unwrap());
    let dispatch = PublicationEffectCommand::dispatch("dispatch-1", &scope, CONTEXT, &capability);
    let capability = applied(ledger.dispatch_command(&dispatch, capability).unwrap());
    let uncertain = PublicationEffectCommand::mark_uncertain("uncertain-1", &scope, &capability);
    let capability = applied(
        ledger
            .mark_uncertain_command(&uncertain, capability)
            .unwrap(),
    );
    let reconcile = PublicationEffectCommand::reconcile(
        "reconcile-1",
        &scope,
        &capability,
        result,
        Digest::fixture([43; 32]),
    );
    ledger.reconcile_command(&reconcile, capability).unwrap();
    drop(ledger);
    let ledger = DurableFixturePublicationEffectLedger::reopen(&path).unwrap();
    assert_eq!(ledger.replay_command(&reconcile).unwrap().state, want);
    let bytes = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(bytes.contains(&format!("\"kind\":\"{}\"", reconcile.kind())));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn succeeded_absent_and_inconclusive_reconcile_commands_each_replay() {
    reconcile_replay(
        ReconcileOutcome::Succeeded,
        PublicationEffectState::ReconciledSucceeded,
        "reconcile-succeeded",
    );
    reconcile_replay(
        ReconcileOutcome::Absent,
        PublicationEffectState::ReconciledAbsent,
        "reconcile-absent",
    );
    reconcile_replay(
        ReconcileOutcome::Inconclusive,
        PublicationEffectState::Blocked,
        "reconcile-inconclusive",
    );
}

#[test]
fn command_fingerprint_has_a_hand_derived_domain_separated_vector() {
    let command = PublicationEffectCommand::claim("claim-1", &scope(1), CONTEXT);
    assert_eq!(
        command.fingerprint().unwrap().to_hex(),
        "ecaa4d51b4a06199184fb4233903a2768cafe1ecefedb4121756f7b21ee5e6fa"
    );
}

#[test]
fn rust_intent_and_ledger_bytes_match_and_round_trip_full_goldens() {
    let scope = scope(1);
    assert_eq!(
        crate::publication_effect_intent::encode_intent(&scope).unwrap(),
        include_bytes!("../tests/fixtures/publication_effect_intent_v1.json")
    );
    let mut ledger = crate::publication_effect_ledger::FixturePublicationEffectLedger::default();
    ledger
        .claim_command(&PublicationEffectCommand::claim("claim-1", &scope, CONTEXT))
        .unwrap();
    let bytes = crate::publication_effect_durable::encode_ledger(&ledger).unwrap();
    let golden = include_bytes!("../tests/fixtures/publication_effect_ledger_v1.json");
    assert_eq!(bytes, golden);
    let decoded = crate::publication_effect_durable::decode_ledger(golden).unwrap();
    assert_eq!(
        crate::publication_effect_durable::encode_ledger(&decoded).unwrap(),
        golden
    );
}
