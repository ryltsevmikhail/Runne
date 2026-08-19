use runne_local_store::{
    BoundedCanonicalId, ClientMutationDisposition, LocalStore, MutationIdentity, MutationOperation,
    MutationTargetKind, MutationTransitionMetadata,
};
use runne_secure_store::test_support::DeterministicSecureStore;

#[test]
fn legacy_metadata_cannot_bypass_the_v7_normalized_command_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let secure = DeterministicSecureStore::new([31; 32]);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, [31; 32])
            .unwrap();
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::WorkspaceOpen,
        MutationTargetKind::Workspace,
        id(),
        "legacy",
        1,
        [3; 32],
    )
    .unwrap();
    assert!(
        store
            .prepare_anchored_mutation(&secure, identity.clone())
            .is_err()
    );
    let metadata = MutationTransitionMetadata::new(None, None, None, "dispatch", 1).unwrap();
    assert!(
        store
            .transition_anchored_mutation_with_metadata(
                &secure,
                identity,
                ClientMutationDisposition::Dispatching,
                metadata,
            )
            .is_err()
    );
}

fn id() -> BoundedCanonicalId {
    BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000010").unwrap()
}
