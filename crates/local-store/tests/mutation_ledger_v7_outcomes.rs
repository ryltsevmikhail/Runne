use gocode_local_store::{
    BoundedCanonicalId, CanonicalMutationOutcome, GenerationAssistant, GenerationFailureReason,
    GenerationTerminal, LedgerMessage, LocalStore, MessageRole, MutationIdentity,
    MutationOperation, MutationTargetKind, NormalizedMutationCommand, V7MutationTransition,
};
use gocode_secure_store::test_support::DeterministicSecureStore;

#[test]
fn v7_authoritative_outcome_families_round_trip_and_reject_trailing() {
    for outcome in outcomes() {
        let bytes = outcome.encode().unwrap();
        assert_eq!(CanonicalMutationOutcome::decode(&bytes).unwrap(), outcome);
        assert!(CanonicalMutationOutcome::decode(&[bytes, vec![0]].concat()).is_err());
    }
}

#[test]
fn v7_generation_terminals_reject_bad_linkage_and_roles() {
    for terminal in [
        GenerationTerminal::Completed,
        GenerationTerminal::Rejected,
        GenerationTerminal::Prohibited,
    ] {
        let outcome = generation(terminal, MessageRole::User, false);
        let bytes = outcome.encode().unwrap();
        assert_eq!(CanonicalMutationOutcome::decode(&bytes).unwrap(), outcome);
    }
    assert!(
        generation(GenerationTerminal::Completed, MessageRole::Assistant, false)
            .encode()
            .is_err()
    );
    assert!(
        generation(GenerationTerminal::Completed, MessageRole::User, true)
            .encode()
            .is_err()
    );
}

#[test]
fn v7_generation_rejection_reason_is_one_closed_tag() {
    let rejected = generation(GenerationTerminal::Rejected, MessageRole::User, false);
    let mut encoded = rejected.encode().unwrap();
    *encoded.last_mut().unwrap() = 9;
    assert!(CanonicalMutationOutcome::decode(&encoded).is_err());
}

#[test]
fn v7_generation_outcomes_round_trip_at_the_message_boundary() {
    for terminal in [
        GenerationTerminal::Completed,
        GenerationTerminal::Rejected,
        GenerationTerminal::Prohibited,
    ] {
        let outcome = generation_with_text(terminal, "x".repeat(64 * 1024));
        let bytes = outcome.encode().unwrap();
        assert_eq!(CanonicalMutationOutcome::decode(&bytes).unwrap(), outcome);
    }
}

#[test]
fn v7_outcome_mismatch_does_not_correlate_to_command() {
    let directory = tempfile::tempdir().unwrap();
    let secure = DeterministicSecureStore::new([88; 32]);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, [88; 32])
            .unwrap();
    let identity = MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::WorkspaceOpen,
        MutationTargetKind::Workspace,
        id("workspace"),
        "mismatch",
        2,
        [3; 32],
    )
    .unwrap();
    let command = NormalizedMutationCommand::OpenWorkspace {
        workspace_id: id("workspace"),
        expected_version: 2,
    };
    store
        .prepare_anchored_mutation_v7(&secure, identity.clone(), command)
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
    let outcome = CanonicalMutationOutcome::WorkspaceOpen {
        workspace_id: id("workspace"),
        new_version: 2,
    };
    assert!(
        store
            .transition_anchored_mutation_v7(
                &secure,
                identity,
                V7MutationTransition::CanonicalOutcome {
                    outcome: Box::new(outcome),
                    summary: "mismatch".into(),
                    timestamp: 3
                }
            )
            .is_err()
    );
}

fn outcomes() -> Vec<CanonicalMutationOutcome> {
    let project = id("project");
    let workspace = id("workspace");
    let conversation = id("conversation");
    vec![
        CanonicalMutationOutcome::ProjectCreate {
            project_id: project.clone(),
            new_version: 1,
        },
        CanonicalMutationOutcome::ProjectArchive {
            project_id: project.clone(),
            new_version: 3,
        },
        CanonicalMutationOutcome::ProjectDelete {
            project_id: project,
            new_version: 3,
        },
        CanonicalMutationOutcome::WorkspaceCreate {
            workspace_id: workspace.clone(),
            new_version: 1,
        },
        CanonicalMutationOutcome::WorkspaceBindRoot {
            workspace_id: workspace.clone(),
            new_version: 3,
        },
        CanonicalMutationOutcome::WorkspaceOpen {
            workspace_id: workspace.clone(),
            new_version: 3,
        },
        CanonicalMutationOutcome::ConversationCreate {
            conversation_id: conversation,
            workspace_id: workspace,
            stream_version: 1,
            committed_at: 1,
        },
    ]
}

fn generation(
    terminal: GenerationTerminal,
    role: MessageRole,
    same_id: bool,
) -> CanonicalMutationOutcome {
    generation_with(terminal, role, same_id, "prompt".into())
}

fn generation_with_text(terminal: GenerationTerminal, text: String) -> CanonicalMutationOutcome {
    generation_with(terminal, MessageRole::User, false, text)
}

fn generation_with(
    terminal: GenerationTerminal,
    role: MessageRole,
    same_id: bool,
    text: String,
) -> CanonicalMutationOutcome {
    let task = id("task");
    let attempt = id("attempt");
    let user = LedgerMessage {
        message_id: id("user"),
        role,
        task_run_id: task.clone(),
        attempt_id: attempt.clone(),
        text: text.clone(),
        committed_at: 1,
    };
    let assistant = if terminal == GenerationTerminal::Completed {
        GenerationAssistant::Completed(LedgerMessage {
            message_id: if same_id { id("user") } else { id("assistant") },
            role: MessageRole::Assistant,
            task_run_id: task.clone(),
            attempt_id: attempt.clone(),
            text,
            committed_at: 2,
        })
    } else {
        GenerationAssistant::Rejected {
            reserved_message_id: id("reserved"),
            reason: GenerationFailureReason::ProviderOutputRejected,
        }
    };
    CanonicalMutationOutcome::Generation {
        terminal,
        conversation_id: id("conversation"),
        task_run_id: task,
        attempt_id: attempt,
        conversation_stream_version: 2,
        task_run_stream_version: 2,
        user_message: user,
        assistant: Box::new(assistant),
    }
}

fn id(value: &str) -> BoundedCanonicalId {
    BoundedCanonicalId::parse(canonical_id(value).as_bytes()).unwrap()
}

fn canonical_id(value: &str) -> String {
    let hash = value.bytes().fold(0_u64, |hash, byte| {
        hash.wrapping_mul(16_777_619).wrapping_add(u64::from(byte))
    });
    format!(
        "018f2e3a-7000-7000-8000-{:012x}",
        hash & 0x0000_ffff_ffff_ffff
    )
}
