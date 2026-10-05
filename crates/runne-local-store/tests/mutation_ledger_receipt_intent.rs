use runne_local_store::{
    BoundedCanonicalId, CanonicalMutationOutcome, ClientMutationDisposition, LocalStore,
    MutationIdentity, MutationOperation, MutationRecoveryBinding, MutationTargetKind,
    NormalizedMutationCommand, V7MutationTransition,
};
use runne_secure_store::test_support::DeterministicSecureStore;

const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000081";

#[test]
fn exact_receipt_lookup_returns_terminal_evidence_without_writing() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [84; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let identity = project_identity("receipt-terminal", [8; 32], [9; 32], 10);
    let command =
        NormalizedMutationCommand::create_project(project_id(), "Project 8".into()).unwrap();
    store
        .prepare_anchored_mutation_v7(&secure, identity.clone(), command.clone())
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::Dispatching { timestamp: 1 },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::Observing { timestamp: 2 },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity,
            V7MutationTransition::CanonicalOutcome {
                outcome: Box::new(CanonicalMutationOutcome::ProjectCreate {
                    project_id: project_id(),
                    new_version: 1,
                }),
                summary: "created".into(),
                timestamp: 3,
            },
        )
        .unwrap();
    let before = root(&path);
    drop(store);

    let mut reopened = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let binding = MutationRecoveryBinding::new([8; 32], [9; 32]).unwrap();
    let receipt = reopened
        .lookup_anchored_mutation_receipt_v7(&secure, binding, "receipt-terminal")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.runtime_identity_digest(), [8; 32]);
    assert_eq!(receipt.principal_digest(), [9; 32]);
    assert_eq!(
        receipt.record().identity().idempotency_key(),
        "receipt-terminal"
    );
    assert_eq!(receipt.record().normalized_command(), Some(&command));
    assert_eq!(
        receipt.record().disposition(),
        ClientMutationDisposition::CanonicalOutcome
    );
    assert!(matches!(
        receipt.record().canonical_outcome(),
        Some(CanonicalMutationOutcome::ProjectCreate { new_version: 1, .. })
    ));
    assert!(
        reopened
            .lookup_anchored_mutation_receipt_v7(
                &secure,
                MutationRecoveryBinding::new([7; 32], [9; 32]).unwrap(),
                "receipt-terminal"
            )
            .is_err()
    );
    assert!(
        reopened
            .lookup_anchored_mutation_receipt_v7(&secure, binding, "absent")
            .unwrap()
            .is_none()
    );
    assert_eq!(root(&path), before);
}

#[test]
fn explicit_taskrun_submit_intent_requires_resolved_accepted_history() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [85; 32];
    let secure = DeterministicSecureStore::new(profile);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile)
            .unwrap();
    let binding = ([10; 32], [11; 32]);
    let conversation = canonical_id("intent-conversation");
    let workspace = canonical_id("intent-workspace");
    let first = submit_identity("intent-1", binding, &conversation, [12; 32]);
    let first_command = submit_command(&conversation, &workspace, "same prompt");
    store
        .prepare_anchored_taskrun_submit_intent_v7(&secure, first.clone(), first_command)
        .unwrap();
    let receipt_binding = MutationRecoveryBinding::new(binding.0, binding.1).unwrap();
    assert_eq!(
        store
            .lookup_anchored_mutation_receipt_v7(&secure, receipt_binding, "intent-1")
            .unwrap()
            .unwrap()
            .record()
            .disposition(),
        ClientMutationDisposition::Prepared
    );
    assert!(
        store
            .prepare_anchored_taskrun_submit_intent_v7(
                &secure,
                submit_identity("intent-2", binding, &conversation, [13; 32]),
                submit_command(&conversation, &workspace, "different prompt")
            )
            .is_err()
    );
    complete_submit(&mut store, &secure, first, 21);

    let second = submit_identity("intent-2", binding, &conversation, [12; 32]);
    let second_command = submit_command(&conversation, &workspace, "same prompt");
    assert_eq!(
        store
            .prepare_anchored_taskrun_submit_intent_v7(
                &secure,
                second.clone(),
                second_command.clone()
            )
            .unwrap()
            .disposition(),
        ClientMutationDisposition::Prepared
    );
    assert_eq!(
        store
            .prepare_anchored_mutation_v7(&secure, second.clone(), second_command.clone())
            .unwrap()
            .disposition(),
        ClientMutationDisposition::Prepared
    );
    assert_eq!(
        store
            .prepare_anchored_taskrun_submit_intent_v7(&secure, second, second_command.clone())
            .unwrap()
            .record()
            .normalized_command(),
        Some(&second_command)
    );
    let second_identity = submit_identity("intent-2", binding, &conversation, [12; 32]);
    complete_submit(&mut store, &secure, second_identity.clone(), 50);
    assert_eq!(
        store
            .prepare_anchored_mutation_v7(&secure, second_identity, second_command)
            .unwrap()
            .disposition(),
        ClientMutationDisposition::CanonicalOutcome
    );
    let third = submit_identity("intent-3", binding, &conversation, [14; 32]);
    let changed_prompt = submit_command(&conversation, &workspace, "next prompt");
    assert_eq!(
        store
            .prepare_anchored_taskrun_submit_intent_v7(&secure, third, changed_prompt)
            .unwrap()
            .disposition(),
        ClientMutationDisposition::Prepared
    );
}

fn submit_identity(
    key: &str,
    binding: ([u8; 32], [u8; 32]),
    conversation: &BoundedCanonicalId,
    semantic: [u8; 32],
) -> MutationIdentity {
    MutationIdentity::new(
        binding.0,
        binding.1,
        MutationOperation::TaskRunSubmit,
        MutationTargetKind::Conversation,
        conversation.clone(),
        key,
        0,
        semantic,
    )
    .unwrap()
}

fn submit_command(
    conversation: &BoundedCanonicalId,
    workspace: &BoundedCanonicalId,
    prompt: &str,
) -> NormalizedMutationCommand {
    NormalizedMutationCommand::SubmitTaskRun {
        conversation_id: conversation.clone(),
        workspace_id: workspace.clone(),
        prompt: prompt.into(),
    }
}

fn complete_submit(
    store: &mut LocalStore,
    secure: &DeterministicSecureStore,
    identity: MutationIdentity,
    timestamp: u64,
) {
    store
        .transition_anchored_mutation_v7(
            secure,
            identity.clone(),
            V7MutationTransition::Dispatching { timestamp },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            secure,
            identity.clone(),
            V7MutationTransition::Observing {
                timestamp: timestamp + 1,
            },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            secure,
            identity,
            V7MutationTransition::CanonicalOutcome {
                outcome: Box::new(CanonicalMutationOutcome::TaskRunSubmitted {
                    task_run_id: canonical_id("submitted-task"),
                    new_version: 2,
                }),
                summary: "accepted".into(),
                timestamp: timestamp + 2,
            },
        )
        .unwrap();
}

fn project_identity(
    key: &str,
    runtime: [u8; 32],
    principal: [u8; 32],
    semantic: u8,
) -> MutationIdentity {
    MutationIdentity::new(
        runtime,
        principal,
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        project_id(),
        key,
        0,
        [semantic; 32],
    )
    .unwrap()
}

fn project_id() -> BoundedCanonicalId {
    BoundedCanonicalId::parse(PROJECT.as_bytes()).unwrap()
}

fn root(path: &std::path::Path) -> (i64, String, i64) {
    rusqlite::Connection::open(path).unwrap().query_row(
        "SELECT db_generation,last_transaction_digest,(SELECT COUNT(*) FROM security_transactions) FROM meta WHERE singleton=1",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap()
}

fn canonical_id(value: &str) -> BoundedCanonicalId {
    let hash = value.bytes().fold(0_u64, |hash, byte| {
        hash.wrapping_mul(16_777_619).wrapping_add(u64::from(byte))
    });
    BoundedCanonicalId::parse(
        format!(
            "018f2e3a-7000-7000-8000-{:012x}",
            hash & 0x0000_ffff_ffff_ffff
        )
        .as_bytes(),
    )
    .unwrap()
}
