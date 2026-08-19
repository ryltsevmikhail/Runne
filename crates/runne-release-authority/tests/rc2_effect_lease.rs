#![cfg(feature = "fixture-only")]

use runne_release_authority::{
    CommandId, Digest, DurableFixturePromotionAuthority, EffectLeaseError, PromotionStore,
    Rc2SigningEffectLeaseState, ThresholdFixtureStoreBinding,
};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

#[test]
fn store_reserves_exact_three_slots_and_rejects_replay() {
    let (mut store, id, _) = signing_support::signing_authorized();
    let leases = store.reserve_rc2_signing_effects(&id, 4).unwrap();
    assert_eq!(store.rc2_effect_claims().len(), 3);
    assert!(
        store
            .rc2_effect_claims()
            .iter()
            .all(|claim| claim.state == Rc2SigningEffectLeaseState::Claimed)
    );
    assert_eq!(
        store.reserve_rc2_signing_effects(&id, 4),
        Err(EffectLeaseError::DuplicateClaim)
    );
    let _ = leases;
}

#[test]
fn store_only_leased_raw_effect_native_and_bundle_consumes_all_three_claims() {
    let (mut store, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    let claims = store.rc2_effect_claims();
    assert_eq!(claims.len(), 3);
    assert!(
        claims
            .iter()
            .all(|claim| claim.state == Rc2SigningEffectLeaseState::Completed)
    );
    store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    assert!(store.rc2_effect_claims().is_empty());
}

#[test]
fn global_durable_authority_reopens_exact_reservation_before_dispatch() {
    let path = std::env::temp_dir().join(format!("runne-global-rc2-effect-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (memory, id, _) = signing_support::signing_authorized();
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let mut authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory)
            .unwrap();
    authority.reserve_rc2_signing_effects(&id, 4).unwrap();
    drop(authority);
    let mut authority = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take("linux-appimage")
        .unwrap();
    authority.dispatch_rc2_signing_effects(&id, lease).unwrap();
    drop(authority);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn bundled_effect_namespace_remains_consumed_after_durable_reopen() {
    let path =
        std::env::temp_dir().join(format!("runne-global-rc2-consumed-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (mut consumed, consumed_id, consumed_payloads) = signing_support::signing_authorized();
    let _bundle = signing_support::leased_bundle(&mut consumed, &consumed_id, &consumed_payloads);
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &consumed)
            .unwrap();
    drop(authority);
    let mut authority = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    assert_eq!(
        authority.reserve_rc2_signing_effects(&consumed_id, 4),
        Err(EffectLeaseError::DuplicateClaim)
    );
    drop(authority);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn durable_authority_keeps_claimed_effect_ledger_from_one_source() {
    let path =
        std::env::temp_dir().join(format!("runne-global-rc2-claimed-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (mut source, id, _) = signing_support::signing_authorized();
    source.reserve_rc2_signing_effects(&id, 4).unwrap();
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();

    let authority = DurableFixturePromotionAuthority::create_from_in_memories(
        &path,
        binding.clone(),
        &[&source],
    )
    .unwrap();
    drop(authority);
    let authority = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    assert!(authority.recover_rc2_signing_effects(&id).is_ok());
    drop(authority);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn durable_authority_keeps_claimed_effect_ledger_when_merging_sources() {
    let path = std::env::temp_dir().join(format!("runne-global-rc2-merged-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (mut claimed, id, _) = signing_support::signing_authorized_with("claimed");
    let (other, _, _) = signing_support::rc1_review_with("other");
    claimed.reserve_rc2_signing_effects(&id, 4).unwrap();
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();

    let authority = DurableFixturePromotionAuthority::create_from_in_memories(
        &path,
        binding.clone(),
        &[&claimed, &other],
    )
    .unwrap();
    drop(authority);
    let authority = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    assert!(authority.recover_rc2_signing_effects(&id).is_ok());
    drop(authority);
    std::fs::remove_file(path).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)] // Crash/reopen assertions intentionally share one exact ledger.
fn durable_raw_effect_and_native_replay_after_reopen_is_idempotent() {
    let path = std::env::temp_dir().join(format!(
        "runne-global-rc2-raw-replay-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let (memory, id, payloads) = signing_support::signing_authorized();
    let (authorization, record, claim) = signing_support::first_signing_effect_claim(&payloads);
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let mut authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory)
            .unwrap();
    let lease = authority
        .reserve_rc2_signing_effects(&id, 4)
        .unwrap()
        .take("linux-appimage")
        .unwrap();
    let effect = authority
        .verify_rc2_signing_effect_with_lease(&id, claim, &authorization, lease)
        .unwrap();
    let native = signing_support::native_evidence_for(&record, effect.effect());
    drop(authority);

    let mut authority = DurableFixturePromotionAuthority::reopen(&path, binding.clone()).unwrap();
    let before = std::fs::read(&path).unwrap();
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take("linux-appimage")
        .unwrap();
    assert!(
        authority
            .verify_rc2_signing_effect_with_lease(
                &id,
                signing_support::first_signing_effect_claim_with_expiry(&payloads, 3).2,
                &authorization,
                lease,
            )
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take("linux-appimage")
        .unwrap();
    let effect = authority
        .verify_rc2_signing_effect_with_lease(
            &id,
            signing_support::first_signing_effect_claim(&payloads).2,
            &authorization,
            lease,
        )
        .unwrap();
    authority
        .verify_rc2_native_evidence_closing_lease(&id, native, &record, effect)
        .unwrap();
    drop(authority);

    let mut authority = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take("linux-appimage")
        .unwrap();
    let effect = authority
        .verify_rc2_signing_effect_with_lease(
            &id,
            signing_support::first_signing_effect_claim(&payloads).2,
            &authorization,
            lease,
        )
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(
        authority
            .verify_rc2_native_evidence_closing_lease(
                &id,
                signing_support::native_evidence_for_with_expiry(&record, effect.effect(), 3),
                &record,
                effect,
            )
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let effect = authority
        .verify_rc2_signing_effect_with_lease(
            &id,
            signing_support::first_signing_effect_claim(&payloads).2,
            &authorization,
            authority
                .recover_rc2_signing_effects(&id)
                .unwrap()
                .take("linux-appimage")
                .unwrap(),
        )
        .unwrap();
    let native = signing_support::native_evidence_for(&record, effect.effect());
    assert!(
        authority
            .verify_rc2_native_evidence_closing_lease(&id, native, &record, effect)
            .is_ok()
    );
    drop(authority);
    std::fs::remove_file(path).unwrap();
}
