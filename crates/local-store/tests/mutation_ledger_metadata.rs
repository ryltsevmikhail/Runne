#![allow(clippy::cast_possible_truncation, clippy::type_complexity)]

use gocode_local_store::{
    BoundedCanonicalId, ClientMutationDisposition, CommandRef, LocalStore, MutationIdentity,
    MutationOperation, MutationTargetKind, MutationTransitionMetadata, OutcomeRef,
    RuntimeCommitDisposition,
};
use gocode_secure_store::test_support::DeterministicSecureStore;

#[test]
fn mutation_ledger_persists_transition_metadata() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [16; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::WorkspaceOpen,
        MutationTargetKind::Workspace,
        BoundedCanonicalId::parse(b"workspace-5").expect("id"),
        "metadata",
        0,
        [7; 32],
    )
    .expect("identity");
    store
        .prepare_anchored_mutation(&secure, identity.clone())
        .expect("prepare");
    let metadata = MutationTransitionMetadata::new(
        Some(RuntimeCommitDisposition::DurablyRecorded),
        Some(CommandRef::new([8; 32]).expect("command")),
        Some(OutcomeRef::new([9; 32]).expect("outcome")),
        "recorded",
        42,
    )
    .expect("metadata");
    store
        .transition_anchored_mutation_with_metadata(
            &secure,
            identity,
            ClientMutationDisposition::Dispatching,
            metadata,
        )
        .expect("transition");
    let connection = rusqlite::Connection::open(path).expect("database");
    let row: (String, Option<String>, Option<Vec<u8>>, Option<Vec<u8>>, String, i64) = connection.query_row("SELECT client_disposition,runtime_disposition,command_ref,outcome_ref,recovery_summary,updated_at FROM mutation_ledger", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?))).expect("readback");
    assert_eq!(
        row,
        (
            "dispatching".into(),
            Some("durably_recorded".into()),
            Some(vec![8; 32]),
            Some(vec![9; 32]),
            "recorded".into(),
            42
        )
    );
}

#[test]
fn mutation_ledger_exercises_all_nonterminal_disposition_edges() {
    let edges = [
        &[
            ClientMutationDisposition::Dispatching,
            ClientMutationDisposition::Observing,
            ClientMutationDisposition::CanonicalOutcome,
        ][..],
        &[
            ClientMutationDisposition::Dispatching,
            ClientMutationDisposition::Retryable,
            ClientMutationDisposition::ManualResolution,
        ][..],
        &[
            ClientMutationDisposition::Dispatching,
            ClientMutationDisposition::Reconciling,
            ClientMutationDisposition::Retryable,
            ClientMutationDisposition::Dispatching,
            ClientMutationDisposition::Observing,
            ClientMutationDisposition::Reconciling,
            ClientMutationDisposition::CanonicalOutcome,
        ][..],
        &[
            ClientMutationDisposition::Dispatching,
            ClientMutationDisposition::Reconciling,
            ClientMutationDisposition::ManualResolution,
        ][..],
    ];
    for (index, path) in edges.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary profile");
        let profile = [17 + index as u8; 32];
        let secure = DeterministicSecureStore::new(profile);
        let mut store =
            LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile)
                .expect("admitted");
        let identity = MutationIdentity::new(
            [1; 32],
            [2; 32],
            MutationOperation::WorkspaceOpen,
            MutationTargetKind::Workspace,
            BoundedCanonicalId::parse(b"workspace-6").expect("id"),
            format!("matrix-{index}"),
            0,
            [10; 32],
        )
        .expect("identity");
        store
            .prepare_anchored_mutation(&secure, identity.clone())
            .expect("prepare");
        for state in path {
            store
                .transition_anchored_mutation(&secure, identity.clone(), *state)
                .expect("allowed edge");
        }
    }
}
