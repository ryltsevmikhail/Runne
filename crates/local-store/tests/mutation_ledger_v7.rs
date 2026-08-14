use gocode_local_store::{
    BoundedCanonicalId, CanonicalMutationOutcome, ClientMutationDisposition, LocalStore,
    MutationIdentity, MutationOperation, MutationTargetKind, NormalizedMutationCommand,
    V7MutationTransition,
};
use gocode_secure_store::test_support::DeterministicSecureStore;

const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000001";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000002";
const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000003";

#[test]
fn v7_closed_command_and_outcome_codecs_round_trip_and_fail_closed() {
    let command =
        NormalizedMutationCommand::create_project(id(PROJECT), "Project".into()).expect("command");
    let encoded = command.encode().expect("encode");
    assert_eq!(
        NormalizedMutationCommand::decode(&encoded).unwrap(),
        command
    );
    assert!(NormalizedMutationCommand::decode(&[1, 1, 0]).is_err());

    let outcome = CanonicalMutationOutcome::project(id(PROJECT), 1).expect("outcome");
    let encoded = outcome.encode().expect("encode");
    assert_eq!(CanonicalMutationOutcome::decode(&encoded).unwrap(), outcome);
    assert!(CanonicalMutationOutcome::decode(&[1, 255]).is_err());
}

#[test]
fn v7_codecs_mirror_c2_field_bounds_and_canonical_ids() {
    assert!(BoundedCanonicalId::parse(b"project").is_err());
    assert!(BoundedCanonicalId::parse(b"018F2E3A-7000-7000-8000-000000000001").is_err());
    assert!(BoundedCanonicalId::parse(b"018f2e3a-7000-6000-8000-000000000001").is_err());
    assert!(NormalizedMutationCommand::create_project(id(PROJECT), "n".repeat(256)).is_ok());
    assert!(NormalizedMutationCommand::create_project(id(PROJECT), "n".repeat(257)).is_err());
    assert!(
        NormalizedMutationCommand::GenerateText {
            conversation_id: id(CONVERSATION),
            expected_version: 1,
            text: "m".repeat(64 * 1024),
        }
        .encode()
        .is_ok()
    );
    assert!(
        NormalizedMutationCommand::GenerateText {
            conversation_id: id(CONVERSATION),
            expected_version: 1,
            text: String::new(),
        }
        .encode()
        .is_err()
    );
}

#[test]
fn v7_bind_command_persists_only_the_admission_digest() {
    let command =
        NormalizedMutationCommand::bind_workspace_root(id(WORKSPACE), 1, [9; 32]).expect("command");
    let encoded = command.encode().expect("encode");
    assert!(!String::from_utf8_lossy(&encoded).contains("gocode-root-admission"));
    assert_eq!(
        NormalizedMutationCommand::decode(&encoded).unwrap(),
        command
    );
}

#[test]
fn v7_all_closed_commands_round_trip_and_reject_trailing_data() {
    let commands = [
        NormalizedMutationCommand::create_project(id(PROJECT), "Project".into()).unwrap(),
        NormalizedMutationCommand::ArchiveProject {
            project_id: id(PROJECT),
            expected_version: 1,
        },
        NormalizedMutationCommand::DeleteProject {
            project_id: id(PROJECT),
            expected_version: 1,
        },
        NormalizedMutationCommand::CreateWorkspace {
            workspace_id: id(WORKSPACE),
            project_id: id(PROJECT),
            display_name: "Workspace".into(),
        },
        NormalizedMutationCommand::bind_workspace_root(id(WORKSPACE), 1, [9; 32]).unwrap(),
        NormalizedMutationCommand::OpenWorkspace {
            workspace_id: id(WORKSPACE),
            expected_version: 1,
        },
        NormalizedMutationCommand::CreateConversation {
            conversation_id: id("conversation"),
            workspace_id: id(WORKSPACE),
        },
        NormalizedMutationCommand::GenerateText {
            conversation_id: id("conversation"),
            expected_version: 1,
            text: "hello".into(),
        },
    ];
    for command in commands {
        let bytes = command.encode().unwrap();
        assert_eq!(NormalizedMutationCommand::decode(&bytes).unwrap(), command);
        assert!(NormalizedMutationCommand::decode(&[bytes, vec![0]].concat()).is_err());
    }
}

#[test]
fn v7_exact_retry_and_outcome_transitions_are_anchored() {
    let directory = tempfile::tempdir().unwrap();
    let secure = DeterministicSecureStore::new([7; 32]);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, [7; 32]).unwrap();
    let retry_identity = identity(
        "retry",
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        PROJECT,
        0,
    );
    let command = NormalizedMutationCommand::create_project(id(PROJECT), "Project".into()).unwrap();
    store
        .prepare_anchored_mutation_v7(&secure, retry_identity.clone(), command)
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            retry_identity.clone(),
            V7MutationTransition::Dispatching { timestamp: 1 },
        )
        .unwrap();
    let retry = store
        .transition_anchored_mutation_v7(
            &secure,
            retry_identity.clone(),
            V7MutationTransition::NotCommittedRetryable { timestamp: 2 },
        )
        .unwrap();
    assert_eq!(retry.disposition(), ClientMutationDisposition::Retryable);
    assert_eq!(retry.record().resend_count(), 0);
    assert!(
        store
            .transition_anchored_mutation_v7(
                &secure,
                retry_identity.clone(),
                V7MutationTransition::Dispatching { timestamp: 3 },
            )
            .is_err()
    );
    let resent = store
        .resend_anchored_mutation_v7(&secure, retry_identity.clone(), 4)
        .unwrap();
    assert_eq!(resent.record().resend_count(), 1);
    store
        .transition_anchored_mutation_v7(
            &secure,
            retry_identity.clone(),
            V7MutationTransition::NotCommittedRetryable { timestamp: 5 },
        )
        .unwrap();
    assert!(
        store
            .resend_anchored_mutation_v7(&secure, retry_identity, 6)
            .is_err()
    );

    assert_canonical_outcome_transition(&mut store, &secure);
}

fn assert_canonical_outcome_transition(store: &mut LocalStore, secure: &DeterministicSecureStore) {
    let committed = identity(
        "outcome",
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        "committed-project",
        0,
    );
    store
        .prepare_anchored_mutation_v7(
            secure,
            committed.clone(),
            NormalizedMutationCommand::create_project(id("committed-project"), "Project".into())
                .unwrap(),
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            secure,
            committed.clone(),
            V7MutationTransition::Dispatching { timestamp: 6 },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            secure,
            committed.clone(),
            V7MutationTransition::Observing { timestamp: 7 },
        )
        .unwrap();
    let permit = store
        .transition_anchored_mutation_v7(
            secure,
            committed,
            V7MutationTransition::CanonicalOutcome {
                outcome: Box::new(
                    CanonicalMutationOutcome::project(id("committed-project"), 1).unwrap(),
                ),
                summary: "committed".into(),
                timestamp: 8,
            },
        )
        .unwrap();
    assert_eq!(
        permit.disposition(),
        ClientMutationDisposition::CanonicalOutcome
    );
}

#[test]
fn legacy_mutation_apis_cannot_create_an_unbound_v7_record() {
    let directory = tempfile::tempdir().unwrap();
    let secure = DeterministicSecureStore::new([7; 32]);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, [7; 32])
            .unwrap();
    let identity = identity(
        "legacy",
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        PROJECT,
        0,
    );
    assert!(store.prepare_anchored_mutation(&secure, identity).is_err());
    let rows: i64 = rusqlite::Connection::open(directory.path().join("profile.sqlite3"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM mutation_ledger", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn v7_prepare_binds_the_exact_command_to_the_identity() {
    let directory = tempfile::tempdir().unwrap();
    let secure = DeterministicSecureStore::new([7; 32]);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, [7; 32]).unwrap();
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        id(PROJECT),
        "v7-command",
        0,
        [3; 32],
    )
    .unwrap();
    let command = NormalizedMutationCommand::create_project(id(PROJECT), "Project".into()).unwrap();
    let permit = store
        .prepare_anchored_mutation_v7(&secure, identity.clone(), command.clone())
        .unwrap();
    assert_eq!(permit.record().normalized_command(), Some(&command));
    let bytes: Vec<u8> = rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT normalized_command FROM mutation_ledger",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(NormalizedMutationCommand::decode(&bytes).unwrap(), command);
    let wrong = NormalizedMutationCommand::create_project(id(WORKSPACE), "Project".into()).unwrap();
    assert!(
        store
            .prepare_anchored_mutation_v7(&secure, identity, wrong)
            .is_err()
    );
}

include!("support/mutation_ledger_v7.rs");
