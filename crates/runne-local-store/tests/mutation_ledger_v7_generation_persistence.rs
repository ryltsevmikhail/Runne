use runne_local_store::{
    BoundedCanonicalId, CanonicalMutationOutcome, GenerationAssistant, GenerationFailureReason,
    GenerationTerminal, LedgerMessage, LocalStore, MessageRole, MutationIdentity,
    MutationOperation, MutationTargetKind, NormalizedMutationCommand, V7MutationTransition,
};
use runne_secure_store::test_support::DeterministicSecureStore;

#[test]
fn boundary_generation_outcomes_persist_and_reopen_for_every_terminal() {
    for terminal in [
        GenerationTerminal::Completed,
        GenerationTerminal::Rejected,
        GenerationTerminal::Prohibited,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let secure = DeterministicSecureStore::new([99; 32]);
        let path = directory.path().join("profile.sqlite3");
        let text = "x".repeat(64 * 1024);
        let identity = identity(terminal);
        let command = command(text.clone());
        let outcome = outcome(terminal, text);
        let mut store = LocalStore::open_anchored(&path, &secure, [99; 32]).unwrap();
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
                identity.clone(),
                V7MutationTransition::CanonicalOutcome {
                    outcome: Box::new(outcome.clone()),
                    summary: "committed".into(),
                    timestamp: 3,
                },
            )
            .unwrap();
        drop(store);
        let mut reopened = LocalStore::open_anchored(&path, &secure, [99; 32]).unwrap();
        let permit = reopened
            .prepare_anchored_mutation_v7(&secure, identity, command)
            .unwrap();
        assert_eq!(permit.record().canonical_outcome(), Some(&outcome));
    }
}

#[test]
fn oversized_generation_outcome_leaves_the_ledger_and_anchor_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let secure = DeterministicSecureStore::new([100; 32]);
    let path = directory.path().join("profile.sqlite3");
    let identity = identity(GenerationTerminal::Completed);
    let command = command("x".repeat(64 * 1024));
    let mut store = LocalStore::open_anchored(&path, &secure, [100; 32]).unwrap();
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
    let observing = store
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            V7MutationTransition::Observing { timestamp: 2 },
        )
        .unwrap();
    let valid_text = "x".repeat(64 * 1024);
    let mut oversized = outcome(GenerationTerminal::Completed, valid_text);
    let CanonicalMutationOutcome::Generation { assistant, .. } = &mut oversized else {
        unreachable!("completed generation outcome")
    };
    let GenerationAssistant::Completed(message) = &mut **assistant else {
        unreachable!("completed assistant")
    };
    message.text.push('x');
    assert!(
        store
            .transition_anchored_mutation_v7(
                &secure,
                identity.clone(),
                V7MutationTransition::CanonicalOutcome {
                    outcome: Box::new(oversized),
                    summary: "too-large".into(),
                    timestamp: 3,
                },
            )
            .is_err()
    );
    let duplicate = store
        .prepare_anchored_mutation_v7(&secure, identity, command)
        .unwrap();
    assert_eq!(duplicate.generation(), observing.generation());
    assert_eq!(duplicate.record().canonical_outcome(), None);
}

fn command(text: String) -> NormalizedMutationCommand {
    NormalizedMutationCommand::GenerateText {
        conversation_id: id(1),
        expected_version: 1,
        text,
    }
}

fn outcome(terminal: GenerationTerminal, text: String) -> CanonicalMutationOutcome {
    let task = id(2);
    let attempt = id(3);
    let user = LedgerMessage {
        message_id: id(4),
        role: MessageRole::User,
        task_run_id: task.clone(),
        attempt_id: attempt.clone(),
        text: text.clone(),
        committed_at: 1,
    };
    let assistant = match terminal {
        GenerationTerminal::Completed => GenerationAssistant::Completed(LedgerMessage {
            message_id: id(5),
            role: MessageRole::Assistant,
            task_run_id: task.clone(),
            attempt_id: attempt.clone(),
            text,
            committed_at: 2,
        }),
        GenerationTerminal::Rejected | GenerationTerminal::Prohibited => {
            GenerationAssistant::Rejected {
                reserved_message_id: id(6),
                reason: GenerationFailureReason::ProviderOutputRejected,
            }
        }
    };
    CanonicalMutationOutcome::Generation {
        terminal,
        conversation_id: id(1),
        task_run_id: task,
        attempt_id: attempt,
        conversation_stream_version: 3,
        task_run_stream_version: 5,
        user_message: user,
        assistant: Box::new(assistant),
    }
}

fn identity(terminal: GenerationTerminal) -> MutationIdentity {
    MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ConversationGenerateText,
        MutationTargetKind::Conversation,
        id(1),
        match terminal {
            GenerationTerminal::Completed => "completed",
            GenerationTerminal::Rejected => "rejected",
            GenerationTerminal::Prohibited => "prohibited",
        },
        1,
        [3; 32],
    )
    .unwrap()
}

fn id(value: u64) -> BoundedCanonicalId {
    BoundedCanonicalId::parse(format!("018f2e3a-7000-7000-8000-{value:012x}").as_bytes()).unwrap()
}
