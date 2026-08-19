#![cfg(feature = "fixture-only")]

use runne_release_authority::{
    AuthorityError, CandidateBinding, CanonicalPayloadKind, CommandId, FixtureAdmission,
    InMemoryPromotionStore, InspectedCanonicalPayload, Mutation, PromotionId, PromotionStore,
    StageTrustFixture, UnprovisionedPromotionStore,
};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

fn binding() -> CandidateBinding {
    CandidateBinding::fixture(
        [0xaa; 32],
        [0xaa; 32],
        verified_stage_support::bootstrap_digest(),
        [0xaa; 32],
        [0xaa; 32],
    )
}

fn inputs() -> (FixtureAdmission, [verified_stage_support::FixtureStage; 3]) {
    let binding = binding();
    let payloads = admission_support::admission_payloads_for(
        &binding.bootstrap().to_hex(),
        &binding.sha256().to_hex(),
    );
    let stages = verified_stage_support::verified_stages(&payloads);
    let manifest = payloads
        .into_iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .map(|(kind, raw)| InspectedCanonicalPayload::parse(kind, &raw).unwrap())
        .unwrap();
    (FixtureAdmission::ingest(binding, manifest).unwrap(), stages)
}

#[test]
fn unprovisioned_store_never_admits_fixture_data() {
    let (admission, _) = inputs();
    assert_eq!(
        UnprovisionedPromotionStore.transact(
            &PromotionId::fixture("p"),
            0,
            CommandId::fixture("c"),
            Mutation::Ingest {
                binding: binding(),
                admission: Box::new(admission)
            },
        ),
        Err(AuthorityError::AuthorityNotProvisioned)
    );
}

#[test]
fn successful_transition_persists_canonical_snapshot_and_exact_replay() {
    let (admission, _) = inputs();
    let mut store = InMemoryPromotionStore::default();
    let promotion = PromotionId::fixture("snapshot");
    let first = store
        .transact(
            &promotion,
            0,
            CommandId::fixture("ingest"),
            Mutation::Ingest {
                binding: binding(),
                admission: Box::new(admission),
            },
        )
        .unwrap();
    let snapshot = store.snapshot(&promotion).unwrap();
    assert_eq!(snapshot.revision, first.revision);
    assert!(
        InspectedCanonicalPayload::parse(CanonicalPayloadKind::Snapshot, &snapshot.bytes).is_ok()
    );
    assert_eq!(
        store.transact(
            &promotion,
            0,
            CommandId::fixture("ingest"),
            Mutation::StartRc1Review {},
        ),
        Err(AuthorityError::CommandReplayDiverged),
    );
    assert_eq!(store.snapshot(&promotion).unwrap(), snapshot);
}

#[test]
fn promotion_identifier_rejects_json_control_characters() {
    assert_eq!(
        PromotionId::try_fixture("bad\"id"),
        Err(AuthorityError::NonCanonicalPayload)
    );
}

#[test]
fn command_replay_rejects_a_different_ingest_binding() {
    let (admission, _) = inputs();
    let mut store = InMemoryPromotionStore::default();
    let promotion = PromotionId::fixture("replay-content");
    store
        .transact(
            &promotion,
            0,
            CommandId::fixture("ingest"),
            Mutation::Ingest {
                binding: binding(),
                admission: Box::new(admission),
            },
        )
        .unwrap();
    let other =
        CandidateBinding::fixture([0xaa; 32], [0xaa; 32], [0xbb; 32], [0xaa; 32], [0xaa; 32]);
    let manifest = InspectedCanonicalPayload::parse(
        CanonicalPayloadKind::UnsignedManifest,
        &admission_support::admission_payloads_for(
            &other.bootstrap().to_hex(),
            &other.sha256().to_hex(),
        )
        .into_iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .unwrap()
        .1,
    )
    .unwrap();
    assert_eq!(
        store.transact(
            &promotion,
            0,
            CommandId::fixture("ingest"),
            Mutation::Ingest {
                binding: other,
                admission: Box::new(FixtureAdmission::ingest(other, manifest).unwrap())
            },
        ),
        Err(AuthorityError::CommandReplayDiverged),
    );
}

#[test]
fn future_stage_handle_cannot_substitute_for_rc1_or_rc2() {
    let (admission, [rc1, rc2, rc3]) = inputs();
    let mut store = InMemoryPromotionStore::default();
    let promotion = PromotionId::fixture("p");
    store
        .transact(
            &promotion,
            0,
            CommandId::fixture("i"),
            Mutation::Ingest {
                binding: binding(),
                admission: Box::new(admission),
            },
        )
        .unwrap();
    store
        .transact(
            &promotion,
            1,
            CommandId::fixture("r"),
            Mutation::StartRc1Review {},
        )
        .unwrap();
    assert_eq!(
        store.transact(
            &promotion,
            2,
            CommandId::fixture("bad"),
            Mutation::QualifyUnsigned {
                transition: Box::new(
                    rc2.transition(
                        runne_promotion_contracts::StageTransitionReservation::new(
                            "p".into(),
                            2,
                            "bad".into(),
                            runne_promotion_contracts::CanonicalPayloadKind::Rc2Authorization,
                            [2; 32],
                        )
                        .unwrap()
                    )
                )
            }
        ),
        Err(AuthorityError::InvalidTransition)
    );
    rc1.commit(&mut store, &promotion, 2, CommandId::fixture("q"))
        .unwrap();
    assert_eq!(
        rc3.raw().commit(
            &mut store,
            &promotion,
            3,
            CommandId::fixture("bad2"),
            CanonicalPayloadKind::Rc3Authorization
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
}

#[test]
fn invalid_stage_signature_leaves_no_claim_or_mutation() {
    let (admission, [rc1, _, _]) = inputs();
    let promotion = PromotionId::fixture("recheck");
    let mut store = InMemoryPromotionStore::default();
    store
        .transact(
            &promotion,
            0,
            CommandId::fixture("i"),
            Mutation::Ingest {
                binding: binding(),
                admission: Box::new(admission),
            },
        )
        .unwrap();
    store
        .transact(
            &promotion,
            1,
            CommandId::fixture("r"),
            Mutation::StartRc1Review {},
        )
        .unwrap();
    let mut raw = rc1.raw();
    raw.corrupt_signature();
    assert_eq!(
        raw.commit(
            &mut store,
            &promotion,
            2,
            CommandId::fixture("q"),
            CanonicalPayloadKind::Rc1Decision
        ),
        Err(AuthorityError::BindingMismatch),
    );
    rc1.commit(&mut store, &promotion, 2, CommandId::fixture("q"))
        .unwrap();
    store
        .set_stage_trust(
            &promotion,
            StageTrustFixture {
                now: 1,
                utc: "2026-08-13T00:00:03Z".into(),
                root_epoch: 2,
                role_floor: 1,
            },
        )
        .unwrap();
    assert_eq!(
        rc1.raw().commit(
            &mut store,
            &promotion,
            2,
            CommandId::fixture("q"),
            CanonicalPayloadKind::Rc1Decision
        ),
        Err(AuthorityError::BindingMismatch),
    );
    store
        .set_stage_trust(
            &promotion,
            StageTrustFixture {
                now: 2,
                utc: "2026-08-13T00:00:03Z".into(),
                root_epoch: 1,
                role_floor: 1,
            },
        )
        .unwrap();
    assert!(
        rc1.raw()
            .commit(
                &mut store,
                &promotion,
                2,
                CommandId::fixture("q"),
                CanonicalPayloadKind::Rc1Decision
            )
            .is_ok()
    );
}
