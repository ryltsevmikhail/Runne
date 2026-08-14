#![allow(
    clippy::cast_possible_truncation,
    clippy::type_complexity,
    clippy::unicode_not_nfc
)]

use gocode_local_store::{
    BoundedCanonicalId, ClientMutationDisposition, LocalStore, MutationIdentity, MutationOperation,
    MutationTargetKind, NormalizedMutationCommand, V7MutationTransition,
};
use gocode_secure_store::test_support::DeterministicSecureStore;

#[test]
fn mutation_ledger_rejects_terminal_and_same_state_transitions() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [22; 32];
    let secure = DeterministicSecureStore::new(profile);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile)
            .expect("admitted");
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        id("project-7"),
        "terminal",
        0,
        [11; 32],
    )
    .expect("identity");
    store
        .prepare_anchored_mutation_v7(&secure, identity.clone(), project("project-7"))
        .expect("prepare");
    assert!(
        store
            .transition_anchored_mutation_v7(
                &secure,
                identity.clone(),
                V7MutationTransition::CanonicalOutcome {
                    outcome: Box::new(
                        gocode_local_store::CanonicalMutationOutcome::project(id("project-7"), 1)
                            .unwrap()
                    ),
                    summary: "early".into(),
                    timestamp: 1
                }
            )
            .is_err()
    );
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::Dispatching { timestamp: 2 },
        )
        .expect("dispatch");
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::Observing { timestamp: 3 },
        )
        .expect("observe");
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::CanonicalOutcome {
                outcome: Box::new(
                    gocode_local_store::CanonicalMutationOutcome::project(id("project-7"), 1)
                        .unwrap(),
                ),
                summary: "committed".into(),
                timestamp: 4,
            },
        )
        .expect("terminal");
    assert!(
        store
            .transition_anchored_mutation_v7(
                &secure,
                identity,
                V7MutationTransition::Indeterminate { timestamp: 5 }
            )
            .is_err()
    );
}

#[test]
fn mutation_ledger_prepares_an_anchored_identity_exactly_once() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [3; 32];
    let secure = DeterministicSecureStore::new(profile);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile)
            .expect("admitted store");
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        id("project-1"),
        "idempotency-1",
        0,
        [4; 32],
    )
    .expect("identity");
    let first = store
        .prepare_anchored_mutation_v7(&secure, identity.clone(), project("project-1"))
        .expect("prepare");
    let duplicate = store
        .prepare_anchored_mutation_v7(&secure, identity, project("project-1"))
        .expect("reuse");
    assert_eq!(first.generation(), duplicate.generation());
    assert_eq!(first.disposition(), ClientMutationDisposition::Prepared);
}

#[test]
fn mutation_ledger_allows_only_closed_disposition_edges() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [13; 32];
    let secure = DeterministicSecureStore::new(profile);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile)
            .expect("admitted");
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        id("project-2"),
        "idempotency-2",
        0,
        [5; 32],
    )
    .expect("identity");
    store
        .prepare_anchored_mutation_v7(&secure, identity.clone(), project("project-2"))
        .expect("prepare");
    assert_eq!(
        store
            .transition_anchored_mutation_v7(
                &secure,
                identity.clone(),
                V7MutationTransition::Dispatching { timestamp: 1 }
            )
            .expect("dispatch")
            .disposition(),
        ClientMutationDisposition::Dispatching
    );
    assert!(
        store
            .transition_anchored_mutation_v7(
                &secure,
                identity,
                V7MutationTransition::CanonicalOutcome {
                    outcome: Box::new(
                        gocode_local_store::CanonicalMutationOutcome::project(id("project-2"), 1)
                            .unwrap()
                    ),
                    summary: "bad".into(),
                    timestamp: 2
                }
            )
            .is_err()
    );
}

#[test]
fn mutation_ledger_accepts_every_closed_operation_target_pair() {
    let pairs = [
        (
            MutationOperation::ProjectCreate,
            MutationTargetKind::Project,
        ),
        (
            MutationOperation::ProjectArchive,
            MutationTargetKind::Project,
        ),
        (
            MutationOperation::ProjectDelete,
            MutationTargetKind::Project,
        ),
        (
            MutationOperation::WorkspaceCreate,
            MutationTargetKind::Workspace,
        ),
        (
            MutationOperation::WorkspaceBindRoot,
            MutationTargetKind::Workspace,
        ),
        (
            MutationOperation::WorkspaceOpen,
            MutationTargetKind::Workspace,
        ),
        (
            MutationOperation::ConversationCreate,
            MutationTargetKind::Conversation,
        ),
        (
            MutationOperation::ConversationGenerateText,
            MutationTargetKind::Conversation,
        ),
        (
            MutationOperation::TaskRunCancel,
            MutationTargetKind::TaskRun,
        ),
        (
            MutationOperation::ApprovalRespond,
            MutationTargetKind::Approval,
        ),
        (MutationOperation::DeviceRevoke, MutationTargetKind::Device),
        (MutationOperation::RuntimeStop, MutationTargetKind::Runtime),
        (MutationOperation::UpdateInstall, MutationTargetKind::Update),
        (MutationOperation::DomainReset, MutationTargetKind::Domain),
    ];
    for (operation, target) in pairs {
        assert!(
            MutationIdentity::new(
                [1; 32],
                [2; 32],
                operation,
                target,
                id("canonical-id"),
                "key",
                0,
                [3; 32]
            )
            .is_ok()
        );
    }
}

#[test]
fn mutation_ledger_rejects_same_key_with_a_different_semantic_digest() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [14; 32];
    let secure = DeterministicSecureStore::new(profile);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile)
            .expect("admitted");
    let make = |digest| {
        MutationIdentity::new(
            [1; 32],
            [2; 32],
            MutationOperation::ProjectCreate,
            MutationTargetKind::Project,
            id("project-3"),
            "same-key",
            0,
            digest,
        )
        .expect("identity")
    };
    store
        .prepare_anchored_mutation_v7(&secure, make([4; 32]), project("project-3"))
        .expect("first");
    assert!(
        store
            .prepare_anchored_mutation_v7(&secure, make([5; 32]), project("project-3"))
            .is_err()
    );
}

#[test]
fn mutation_ledger_reuses_the_original_semantic_command_across_a_new_key() {
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
            MutationOperation::ProjectCreate,
            MutationTargetKind::Project,
            id("project-semantic"),
            key,
            0,
            [6; 32],
        )
        .expect("identity")
    };
    let first = store
        .prepare_anchored_mutation_v7(&secure, make("first-key"), project("project-semantic"))
        .expect("first");
    let second = store
        .prepare_anchored_mutation_v7(&secure, make("second-key"), project("project-semantic"))
        .expect("semantic reuse");
    assert_eq!(first.generation(), second.generation());
}

include!("support/mutation_ledger_support.rs");
