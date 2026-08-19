use runne_local_store::{
    BoundedCanonicalId, CanonicalMutationOutcome, LocalStore, MutationIdentity, MutationOperation,
    MutationTargetKind, NormalizedMutationCommand, V7MutationTransition,
};
use runne_secure_store::test_support::DeterministicSecureStore;

#[test]
fn duplicate_recovers_a_v7_canonical_outcome_from_a_verified_one_ahead_anchor() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [67; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut first = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let mut second = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let id = canonical_id(1);
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        id.clone(),
        "one-ahead",
        0,
        [67; 32],
    )
    .unwrap();
    let command =
        || NormalizedMutationCommand::create_project(id.clone(), "Project".into()).unwrap();
    first
        .prepare_anchored_mutation_v7(&secure, identity.clone(), command())
        .unwrap();
    first
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::Dispatching { timestamp: 1 },
        )
        .unwrap();
    first
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::Observing { timestamp: 2 },
        )
        .unwrap();
    secure.fail_next_advance();
    assert!(
        first
            .transition_anchored_mutation_v7(
                &secure,
                identity.clone(),
                V7MutationTransition::CanonicalOutcome {
                    outcome: Box::new(CanonicalMutationOutcome::project(id.clone(), 1).unwrap()),
                    summary: "outcome".into(),
                    timestamp: 3,
                }
            )
            .is_err()
    );
    let permit = second
        .prepare_anchored_mutation_v7(&secure, identity, command())
        .unwrap();
    assert_eq!(
        permit.disposition(),
        runne_local_store::ClientMutationDisposition::CanonicalOutcome
    );
}

#[test]
fn one_ahead_reopen_cannot_bypass_the_single_resend_budget() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [68; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut first = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let project = canonical_id(2);
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        project.clone(),
        "resend-one-ahead",
        0,
        [68; 32],
    )
    .unwrap();
    first
        .prepare_anchored_mutation_v7(
            &secure,
            identity.clone(),
            NormalizedMutationCommand::create_project(project, "Project".into()).unwrap(),
        )
        .unwrap();
    first
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::Dispatching { timestamp: 1 },
        )
        .unwrap();
    first
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::NotCommittedRetryable { timestamp: 2 },
        )
        .unwrap();
    secure.fail_next_advance();
    assert!(
        first
            .resend_anchored_mutation_v7(&secure, identity.clone(), 3)
            .is_err()
    );
    drop(first);

    let mut reopened = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    reopened
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::NotCommittedRetryable { timestamp: 4 },
        )
        .unwrap();
    assert!(
        reopened
            .transition_anchored_mutation_v7(
                &secure,
                identity.clone(),
                V7MutationTransition::Dispatching { timestamp: 5 },
            )
            .is_err()
    );
    assert!(
        reopened
            .resend_anchored_mutation_v7(&secure, identity, 5)
            .is_err()
    );
}

fn canonical_id(value: u64) -> BoundedCanonicalId {
    BoundedCanonicalId::parse(format!("018f2e3a-7000-7000-8000-{value:012x}").as_bytes()).unwrap()
}
