#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthorityError, CanonicalPayloadKind, CommandId, Digest, DurableFixturePromotionAuthority,
    DurableFixturePromotionStore, PromotionId, StageTrustFixture, ThresholdFixtureStoreBinding,
};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "durable_stage_store_review/provenance.rs"]
mod provenance;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

#[test]
fn single_record_stores_leave_no_raw_stage_claims() {
    let first_path = path("single-record-first");
    let second_path = path("single-record-second");
    cleanup(&first_path);
    cleanup(&second_path);
    let (first_memory, first, payloads) = signing_support::qualified_unsigned_with("first");
    let (second_memory, second, _) = signing_support::qualified_unsigned_with("second");
    let mut first_store = DurableFixturePromotionStore::create_from_in_memory(
        &first_path,
        binding(),
        &first_memory,
        &first,
    )
    .unwrap();
    let mut second_store = DurableFixturePromotionStore::create_from_in_memory(
        &second_path,
        binding(),
        &second_memory,
        &second,
    )
    .unwrap();
    let first_before = std::fs::read(&first_path).unwrap();
    let second_before = std::fs::read(&second_path).unwrap();
    let [_, stage, _] = verified_stage_support::verified_stages(&payloads);

    assert_eq!(
        stage.raw().commit(
            &mut first_store,
            &first,
            3,
            CommandId::fixture("authorize"),
            CanonicalPayloadKind::Rc2Authorization,
        ),
        Err(AuthorityError::AuthorityNotProvisioned)
    );
    assert_eq!(
        stage.raw().commit(
            &mut second_store,
            &second,
            3,
            CommandId::fixture("authorize"),
            CanonicalPayloadKind::Rc2Authorization,
        ),
        Err(AuthorityError::AuthorityNotProvisioned)
    );
    assert_eq!(first_store.snapshot(&first).unwrap().revision, 3);
    assert_eq!(second_store.snapshot(&second).unwrap().revision, 3);
    drop(first_store);
    drop(second_store);
    for (path, before) in [(&first_path, first_before), (&second_path, second_before)] {
        assert_eq!(std::fs::read(path).unwrap(), before);
        cleanup(path);
    }
}

#[test]
fn exact_stage_command_recovers_after_expiry_with_unchanged_trust_epochs() {
    let path = path("expiry-recovery");
    cleanup(&path);
    let (memory, id, payloads) = signing_support::rc1_review_with("recovery");
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let [stage, _, _] = verified_stage_support::verified_stages(&payloads);
    let completed = stage
        .commit(&mut store, &id, 2, CommandId::fixture("qualify"))
        .unwrap();
    store
        .set_stage_trust(
            &id,
            StageTrustFixture {
                now: 5,
                utc: "2026-08-13T00:00:05Z".into(),
                root_epoch: 1,
                role_floor: 1,
            },
        )
        .unwrap();
    drop(store);
    let mut store = DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap();

    assert_eq!(
        stage.commit(&mut store, &id, 2, CommandId::fixture("qualify")),
        Ok(completed)
    );
    drop(store);
    cleanup(&path);
}

#[test]
fn reopen_keeps_historical_claims_after_trust_advancement() {
    let path = path("trust-advancement-reopen");
    cleanup(&path);
    let (memory, id, payloads) = signing_support::rc1_review_with("trust-advancement");
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let [stage, _, _] = verified_stage_support::verified_stages(&payloads);
    stage
        .commit(&mut store, &id, 2, CommandId::fixture("qualify"))
        .unwrap();
    store
        .set_stage_trust(
            &id,
            StageTrustFixture {
                now: 2,
                utc: "2026-08-13T00:00:03Z".into(),
                root_epoch: 2,
                role_floor: 2,
            },
        )
        .unwrap();
    drop(store);
    let store = DurableFixturePromotionAuthority::reopen(&path, binding());
    assert!(store.is_ok());
    drop(store);
    cleanup(&path);
}

#[test]
fn reopen_rejects_historical_claim_role_floor_above_signed_epoch_after_trust_advancement() {
    let path = path("trust-advancement-role-floor-tamper");
    cleanup(&path);
    let (memory, id, payloads) = signing_support::rc1_review_with("trust-role-floor-tamper");
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let [stage, _, _] = verified_stage_support::verified_stages(&payloads);
    stage
        .commit(&mut store, &id, 2, CommandId::fixture("qualify"))
        .unwrap();
    store
        .set_stage_trust(
            &id,
            StageTrustFixture {
                now: 2,
                utc: "2026-08-13T00:00:03Z".into(),
                root_epoch: 2,
                role_floor: 2,
            },
        )
        .unwrap();
    drop(store);
    verified_stage_support::durable_stage_wire::rewrite_stage_claim_role_floor(&path, 2);

    assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_err());
    cleanup(&path);
}

#[test]
fn completed_stage_recovery_requires_the_admitted_trust_epochs() {
    let path = path("trust-advancement-recovery");
    cleanup(&path);
    let (memory, id, payloads) = signing_support::rc1_review_with("trust-recovery");
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let [stage, _, _] = verified_stage_support::verified_stages(&payloads);
    stage
        .commit(&mut store, &id, 2, CommandId::fixture("qualify"))
        .unwrap();
    store
        .set_stage_trust(
            &id,
            StageTrustFixture {
                now: 2,
                utc: "2026-08-13T00:00:03Z".into(),
                root_epoch: 2,
                role_floor: 2,
            },
        )
        .unwrap();
    assert!(
        stage
            .commit(&mut store, &id, 2, CommandId::fixture("qualify"))
            .is_err()
    );
    drop(store);
    cleanup(&path);
}

#[test]
fn new_stage_claims_obey_the_current_role_floor() {
    let path = path("trust-advancement-new-claim");
    cleanup(&path);
    let (memory, id, payloads) = signing_support::rc1_review_with("trust-new-claim");
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let [rc1, rc2, _] = verified_stage_support::verified_stages(&payloads);
    rc1.commit(&mut store, &id, 2, CommandId::fixture("qualify"))
        .unwrap();
    store
        .set_stage_trust(
            &id,
            StageTrustFixture {
                now: 2,
                utc: "2026-08-13T00:00:03Z".into(),
                root_epoch: 1,
                role_floor: 2,
            },
        )
        .unwrap();

    assert!(
        rc2.commit(&mut store, &id, 3, CommandId::fixture("authorize"))
            .is_err()
    );
    drop(store);
    cleanup(&path);
}

#[test]
fn invalid_stage_reservation_commands_leave_the_durable_authority_unchanged() {
    for (index, command) in ["", "Qualify", "qualify\\n"].into_iter().enumerate() {
        let path = path(&format!("invalid-command-{index}"));
        cleanup(&path);
        let (memory, id, payloads) = signing_support::rc1_review_with("invalid-command");
        let mut store =
            DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory)
                .unwrap();
        let before = std::fs::read(&path).unwrap();
        let [stage, _, _] = verified_stage_support::verified_stages(&payloads);

        assert_eq!(
            stage.raw().commit(
                &mut store,
                &id,
                2,
                CommandId::fixture(command),
                CanonicalPayloadKind::Rc1Decision,
            ),
            Err(AuthorityError::NonCanonicalPayload),
            "{command:?}",
        );
        drop(store);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_ok());
        cleanup(&path);
    }
}

#[test]
fn promotion_identifier_uses_the_shared_stage_identifier_corpus() {
    let corpus: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../gocode-promotion-contracts/tests/fixtures/stage_identifier_corpus.json"
    ))
    .unwrap();
    for invalid in corpus["invalid_ids"].as_array().unwrap() {
        assert!(PromotionId::try_fixture(invalid.as_str().unwrap()).is_err());
    }
    assert!(PromotionId::try_fixture("release-1").is_ok());
}

fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap()
}

fn path(case: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "gocode-durable-stage-review-{case}-{}",
        std::process::id()
    ))
}

fn replace_after(path: &std::path::Path, start: &str, needle: &str, replacement: &str) {
    let text = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
    let (head, tail) = text.split_once(start).unwrap();
    assert!(tail.contains(needle));
    std::fs::write(
        path,
        format!("{head}{start}{}", tail.replacen(needle, replacement, 1)),
    )
    .unwrap();
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
}
