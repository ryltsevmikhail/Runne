#![allow(
    clippy::cast_possible_truncation,
    clippy::type_complexity,
    clippy::unicode_not_nfc
)]

use gocode_local_store::{
    BoundedCanonicalId, ClientMutationDisposition, LocalStore, MutationIdentity, MutationOperation,
    MutationTargetKind,
};
use gocode_secure_store::test_support::DeterministicSecureStore;

#[test]
fn mutation_ledger_rejects_a_target_outside_its_closed_operation_matrix() {
    let target = BoundedCanonicalId::parse(b"project-1").expect("canonical target");
    assert!(
        MutationIdentity::new(
            [1; 32],
            [2; 32],
            MutationOperation::WorkspaceOpen,
            MutationTargetKind::Project,
            target,
            "idem-1",
            0,
            [3; 32],
        )
        .is_err()
    );
}

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
        MutationOperation::WorkspaceOpen,
        MutationTargetKind::Workspace,
        BoundedCanonicalId::parse(b"workspace-7").expect("id"),
        "terminal",
        0,
        [11; 32],
    )
    .expect("identity");
    store
        .prepare_anchored_mutation(&secure, identity.clone())
        .expect("prepare");
    assert!(
        store
            .transition_anchored_mutation(
                &secure,
                identity.clone(),
                ClientMutationDisposition::Prepared
            )
            .is_err()
    );
    store
        .transition_anchored_mutation(
            &secure,
            identity.clone(),
            ClientMutationDisposition::Dispatching,
        )
        .expect("dispatch");
    store
        .transition_anchored_mutation(
            &secure,
            identity.clone(),
            ClientMutationDisposition::Observing,
        )
        .expect("observe");
    store
        .transition_anchored_mutation(
            &secure,
            identity.clone(),
            ClientMutationDisposition::CanonicalOutcome,
        )
        .expect("terminal");
    assert!(
        store
            .transition_anchored_mutation(&secure, identity, ClientMutationDisposition::Reconciling)
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
        MutationOperation::WorkspaceOpen,
        MutationTargetKind::Workspace,
        BoundedCanonicalId::parse(b"workspace-1").expect("id"),
        "idempotency-1",
        1,
        [4; 32],
    )
    .expect("identity");
    let first = store
        .prepare_anchored_mutation(&secure, identity.clone())
        .expect("prepare");
    let duplicate = store
        .prepare_anchored_mutation(&secure, identity)
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
        MutationOperation::WorkspaceOpen,
        MutationTargetKind::Workspace,
        BoundedCanonicalId::parse(b"workspace-2").expect("id"),
        "idempotency-2",
        1,
        [5; 32],
    )
    .expect("identity");
    store
        .prepare_anchored_mutation(&secure, identity.clone())
        .expect("prepare");
    assert_eq!(
        store
            .transition_anchored_mutation(
                &secure,
                identity.clone(),
                ClientMutationDisposition::Dispatching
            )
            .expect("dispatch")
            .disposition(),
        ClientMutationDisposition::Dispatching
    );
    assert!(
        store
            .transition_anchored_mutation(
                &secure,
                identity,
                ClientMutationDisposition::CanonicalOutcome
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
                BoundedCanonicalId::parse(b"canonical-id").expect("id"),
                "key",
                0,
                [3; 32]
            )
            .is_ok()
        );
    }
}

#[test]
fn mutation_ledger_rejects_noncanonical_or_control_target_ids() {
    for value in [b"".as_slice(), b"id\n", "ń".as_bytes(), &[b'x'; 129][..]] {
        assert!(BoundedCanonicalId::parse(value).is_err());
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
            MutationOperation::WorkspaceOpen,
            MutationTargetKind::Workspace,
            BoundedCanonicalId::parse(b"workspace-3").expect("id"),
            "same-key",
            0,
            digest,
        )
        .expect("identity")
    };
    store
        .prepare_anchored_mutation(&secure, make([4; 32]))
        .expect("first");
    assert!(
        store
            .prepare_anchored_mutation(&secure, make([5; 32]))
            .is_err()
    );
}

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
            BoundedCanonicalId::parse(b"workspace-4").expect("id"),
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
