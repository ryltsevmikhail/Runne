#![cfg(feature = "fixture-only")]

use runne_release_authority::{
    AuthorityError, CommandId, Digest, DurableFixturePromotionAuthority,
    ThresholdFixtureStoreBinding,
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
fn raw_stage_nonce_cannot_cross_promotion_records_after_reopen() {
    let path =
        std::env::temp_dir().join(format!("runne-global-stage-claims-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
    let (one, first, payloads) = signing_support::rc1_review_with("first");
    let (two, second, _) = signing_support::rc1_review_with("second");
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let mut authority = DurableFixturePromotionAuthority::create_from_in_memories(
        &path,
        binding.clone(),
        &[&one, &two],
    )
    .unwrap();
    let [stage, _, _] = verified_stage_support::verified_stages(&payloads);
    stage
        .commit(&mut authority, &first, 2, CommandId::fixture("qualify"))
        .unwrap();
    drop(authority);
    let mut authority = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    assert_eq!(
        stage.commit(&mut authority, &second, 2, CommandId::fixture("qualify")),
        Err(AuthorityError::BindingMismatch)
    );
    drop(authority);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn global_ledger_rejects_second_live_owner_and_tampering_after_crash() {
    let path =
        std::env::temp_dir().join(format!("runne-global-stage-tamper-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
    let (store, _, _) = signing_support::qualified_unsigned_with("tamper");
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let owner =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &store)
            .unwrap();
    assert!(matches!(
        DurableFixturePromotionAuthority::reopen(&path, binding.clone()),
        Err(AuthorityError::DurableStateUnavailable)
    ));
    drop(owner);
    let mut tampered = std::fs::read(&path).unwrap();
    let offset = tampered.iter().position(|byte| *byte == b'f').unwrap();
    tampered[offset] = b'g';
    std::fs::write(&path, tampered).unwrap();
    assert!(matches!(
        DurableFixturePromotionAuthority::reopen(&path, binding),
        Err(AuthorityError::NonCanonicalPayload)
    ));
    std::fs::remove_file(path).unwrap();
}
