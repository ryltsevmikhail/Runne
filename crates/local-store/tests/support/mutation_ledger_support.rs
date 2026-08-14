#[test]
fn mutation_ledger_allows_prepared_to_close_manual_without_dispatch() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [16; 32];
    let secure = DeterministicSecureStore::new(profile);
    let mut store = LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile).expect("admitted");
    let identity = MutationIdentity::new([1; 32], [2; 32], MutationOperation::ProjectCreate, MutationTargetKind::Project, id("project-prepared-manual"), "prepared-manual", 0, [7; 32]).expect("identity");
    store.prepare_anchored_mutation_v7(&secure, identity.clone(), project("project-prepared-manual")).expect("prepared");
    assert_eq!(store.transition_anchored_mutation_v7(&secure, identity, V7MutationTransition::ManualResolution { summary: "carrierless_prepared".into(), timestamp: 1 }).expect("manual").disposition(), ClientMutationDisposition::ManualResolution);
}

fn project(value: &str) -> NormalizedMutationCommand {
    NormalizedMutationCommand::create_project(id(value), "Project".into()).unwrap()
}

fn id(value: &str) -> BoundedCanonicalId {
    let hash = value.bytes().fold(0_u64, |hash, byte| hash.wrapping_mul(16_777_619).wrapping_add(u64::from(byte)));
    BoundedCanonicalId::parse(format!("018f2e3a-7000-7000-8000-{:012x}", hash & 0x0000_ffff_ffff_ffff).as_bytes()).unwrap()
}

include!("mutation_ledger_poison.rs");

#[test]
fn mutation_ledger_rejects_noncanonical_or_control_target_ids() {
    for value in [b"".as_slice(), b"id\n", "ń".as_bytes(), &[b'x'; 129][..]] {
        assert!(BoundedCanonicalId::parse(value).is_err());
    }
}
