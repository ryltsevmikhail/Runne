use runne_local_store::{
    BoundedCanonicalId, LocalStore, MutationIdentity, MutationOperation, MutationTargetKind,
    NormalizedMutationCommand,
};
use runne_secure_store::test_support::DeterministicSecureStore;

#[test]
fn mutation_ledger_rejects_tamper_before_a_new_prepare() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [19; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let make = |key, digest| {
        MutationIdentity::new(
            [1; 32],
            [2; 32],
            MutationOperation::ProjectCreate,
            MutationTargetKind::Project,
            id(),
            key,
            0,
            digest,
        )
        .expect("identity")
    };
    store
        .prepare_anchored_mutation_v7(&secure, make("first", [19; 32]), command())
        .expect("prepare");
    rusqlite::Connection::open(&path)
        .expect("database")
        .execute("UPDATE mutation_ledger SET target_id=x'78'", [])
        .expect("tamper");
    assert!(
        store
            .prepare_anchored_mutation_v7(&secure, make("second", [20; 32]), command())
            .is_err()
    );
}

fn command() -> NormalizedMutationCommand {
    NormalizedMutationCommand::create_project(id(), "Project".into()).unwrap()
}

fn id() -> BoundedCanonicalId {
    BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000019").unwrap()
}
