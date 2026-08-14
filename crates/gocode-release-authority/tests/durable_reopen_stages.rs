#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    CandidateBinding, CanonicalPayloadKind, CommandId, Digest, DurableFixturePromotionAuthority,
    DurableFixturePromotionStore, FixtureAdmission, InMemoryPromotionStore,
    InspectedCanonicalPayload, Mutation, PromotionId, PromotionState, PromotionStore,
    ThresholdFixtureStoreBinding,
};
use sha2::{Digest as _, Sha256};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

#[test]
fn durable_store_reopens_and_continues_non_authorizing_stage() {
    let path = std::path::Path::new("/dev/shm").join(format!(
        "gocode-durable-reopen-stage-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let (memory, id, _) = at_stage(0);
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let store =
        DurableFixturePromotionStore::create_from_in_memory(&path, binding.clone(), &memory, &id)
            .unwrap();
    drop(store);
    let mut reopened = DurableFixturePromotionStore::reopen(&path, binding).unwrap();
    let outcome = reopened
        .transact(&id, 1, CommandId::fixture("r"), Mutation::StartRc1Review {})
        .unwrap();
    assert_eq!(outcome.state, PromotionState::Rc1Review);
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn durable_single_record_store_leaves_raw_stage_commit_unprovisioned_after_reopen() {
    let path = std::path::Path::new("/dev/shm").join(format!(
        "gocode-durable-stage-reservation-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let (memory, id, payloads) = at_stage(1);
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let store =
        DurableFixturePromotionStore::create_from_in_memory(&path, binding.clone(), &memory, &id)
            .unwrap();
    drop(store);
    let mut reopened = DurableFixturePromotionStore::reopen(&path, binding).unwrap();
    let [rc1, _, _] = verified_stage_support::verified_stages(&payloads);
    assert_eq!(
        rc1.commit(&mut reopened, &id, 2, CommandId::fixture("q")),
        Err(gocode_release_authority::AuthorityError::AuthorityNotProvisioned)
    );
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn durable_store_reopens_full_release_facts_for_exact_rc2_authorization() {
    let path = std::path::Path::new("/dev/shm").join(format!(
        "gocode-durable-release-facts-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let bootstrap = verified_stage_support::bootstrap_digest();
    let provisional = admission_support::admission_payloads_for(&hex(bootstrap), &"aa".repeat(32));
    let manifest = provisional
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .map(|(_, raw)| raw)
        .unwrap();
    let binding = CandidateBinding::fixture_with_release_facts(
        [0xaa; 32],
        [0xaa; 32],
        bootstrap,
        [0xaa; 32],
        [0xaa; 32],
        Sha256::digest(&manifest[..manifest.len() - 1]).into(),
    );
    let payloads = admission_support::admission_payloads_for(
        &binding.bootstrap().to_hex(),
        &binding.sha256().to_hex(),
    );
    let manifest = payloads
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .map(|(kind, raw)| InspectedCanonicalPayload::parse(*kind, raw).unwrap())
        .unwrap();
    let id = PromotionId::fixture("release-facts");
    let mut memory = InMemoryPromotionStore::default();
    memory
        .transact(
            &id,
            0,
            CommandId::fixture("ingest"),
            Mutation::Ingest {
                binding,
                admission: Box::new(FixtureAdmission::ingest(binding, manifest).unwrap()),
            },
        )
        .unwrap();
    memory
        .transact(
            &id,
            1,
            CommandId::fixture("review"),
            Mutation::StartRc1Review {},
        )
        .unwrap();
    let [rc1, rc2, _] = verified_stage_support::verified_stages(&payloads);
    rc1.commit(&mut memory, &id, 2, CommandId::fixture("qualify"))
        .unwrap();
    let durable_binding =
        ThresholdFixtureStoreBinding::new(Digest::fixture(bootstrap), "fixture-v1", 1).unwrap();
    let store = DurableFixturePromotionAuthority::create_from_in_memory(
        &path,
        durable_binding.clone(),
        &memory,
    )
    .unwrap();
    drop(store);
    let mut reopened = DurableFixturePromotionAuthority::reopen(&path, durable_binding).unwrap();
    assert_eq!(
        rc2.commit(&mut reopened, &id, 3, CommandId::fixture("authorize"))
            .unwrap()
            .state,
        PromotionState::SigningAuthorized
    );
    drop(reopened);
    std::fs::remove_file(path).unwrap();
    let _ = std::fs::remove_file(std::path::Path::new("/dev/shm").join(format!(
        "gocode-durable-release-facts-{}.lease",
        std::process::id()
    )));
}

#[test]
fn durable_reopen_rejects_mutated_release_fact_artifact_and_profile() {
    let path = std::path::Path::new("/dev/shm").join(format!(
        "gocode-durable-release-facts-mutation-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let (memory, id, _) = at_stage(0);
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let store =
        DurableFixturePromotionStore::create_from_in_memory(&path, binding.clone(), &memory, &id)
            .unwrap();
    drop(store);

    let source = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    for prefix in [
        "\"artifact_sha256\":",
        "\"profile_id\":\"gocode-bundled-runtime\",\"bundle_sha256\":",
    ] {
        std::fs::write(&path, &source).unwrap();
        mutate_release_fact(&path, prefix);
        assert!(DurableFixturePromotionStore::reopen(&path, binding.clone()).is_err());
    }
    std::fs::remove_file(path).unwrap();
}

fn mutate_release_fact(path: &std::path::Path, prefix: &str) {
    let source = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
    let old = format!("{prefix}\"{}\"", "aa".repeat(32));
    let new = format!("{prefix}\"{}\"", "bb".repeat(32));
    assert_ne!(source, source.replacen(&old, &new, 1));
    std::fs::write(path, source.replacen(&old, &new, 1)).unwrap();
}

fn hex(bytes: [u8; 32]) -> String {
    Digest::fixture(bytes).to_hex()
}

fn at_stage(
    stage: usize,
) -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    let bootstrap = verified_stage_support::bootstrap_digest();
    let provisional = admission_support::admission_payloads_for(&hex(bootstrap), &"aa".repeat(32));
    let manifest = provisional
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .map(|(_, raw)| raw)
        .unwrap();
    let binding = CandidateBinding::fixture_with_release_facts(
        [0xaa; 32],
        [0xaa; 32],
        bootstrap,
        [0xaa; 32],
        [0xaa; 32],
        Sha256::digest(&manifest[..manifest.len() - 1]).into(),
    );
    let payloads = admission_support::admission_payloads_for(
        &binding.bootstrap().to_hex(),
        &binding.sha256().to_hex(),
    );
    let manifest = payloads
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .map(|(kind, raw)| InspectedCanonicalPayload::parse(*kind, raw).unwrap())
        .unwrap();
    let id = PromotionId::fixture("stage");
    let mut store = InMemoryPromotionStore::default();
    store
        .transact(
            &id,
            0,
            CommandId::fixture("i"),
            Mutation::Ingest {
                binding,
                admission: Box::new(FixtureAdmission::ingest(binding, manifest).unwrap()),
            },
        )
        .unwrap();
    if stage >= 1 {
        store
            .transact(&id, 1, CommandId::fixture("r"), Mutation::StartRc1Review {})
            .unwrap();
    }
    if stage >= 2 {
        let [rc1, _, _] = verified_stage_support::verified_stages(&payloads);
        rc1.commit(&mut store, &id, 2, CommandId::fixture("q"))
            .unwrap();
    }
    (store, id, payloads)
}
