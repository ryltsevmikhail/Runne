#[test]
fn mutation_ledger_poisoned_after_anchor_cas_failure() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [15; 32];
    let secure = DeterministicSecureStore::new(profile);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile)
            .expect("admitted");
    let make = |key| {
        MutationIdentity::new(
            [1; 32],
            [2; 32],
            MutationOperation::WorkspaceOpen,
            MutationTargetKind::Workspace,
            id("workspace-4"),
            key,
            0,
            [6; 32],
        )
        .expect("identity")
    };
    secure.fail_next_advance();
    assert!(
        store
            .prepare_anchored_mutation(&secure, make("failed"))
            .is_err()
    );
    assert!(
        store
            .prepare_anchored_mutation(&secure, make("later"))
            .is_err()
    );
}
