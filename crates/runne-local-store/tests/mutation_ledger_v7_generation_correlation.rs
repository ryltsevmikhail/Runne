use runne_local_store::{
    BoundedCanonicalId, CanonicalMutationOutcome, GenerationAssistant, GenerationFailureReason,
    GenerationTerminal, LedgerMessage, MessageRole, NormalizedMutationCommand,
};

#[test]
fn generation_correlation_rejects_every_authoritative_mismatch() {
    let command = command();
    for outcome in valid_terminals() {
        assert!(outcome_matches(&outcome, &command));
    }
    for outcome in invalid_terminals() {
        assert!(!outcome_matches(&outcome, &command));
    }
    assert!(!outcome_matches(&valid_terminals()[0], &overflow_command()));
}

fn command() -> NormalizedMutationCommand {
    NormalizedMutationCommand::GenerateText {
        conversation_id: id("conversation"),
        expected_version: 1,
        text: "prompt".into(),
    }
}
fn valid_terminals() -> [CanonicalMutationOutcome; 3] {
    [
        GenerationTerminal::Completed,
        GenerationTerminal::Rejected,
        GenerationTerminal::Prohibited,
    ]
    .map(|terminal| {
        generation(
            terminal,
            3,
            5,
            MessageRole::User,
            1,
            2,
            GenerationFailureReason::ProviderOutputRejected,
        )
    })
}
fn invalid_terminals() -> [CanonicalMutationOutcome; 4] {
    [
        generation(
            GenerationTerminal::Completed,
            4,
            5,
            MessageRole::User,
            1,
            2,
            GenerationFailureReason::ProviderOutputRejected,
        ),
        generation(
            GenerationTerminal::Rejected,
            3,
            4,
            MessageRole::User,
            1,
            0,
            GenerationFailureReason::ProviderOutputRejected,
        ),
        generation(
            GenerationTerminal::Prohibited,
            3,
            5,
            MessageRole::Assistant,
            1,
            0,
            GenerationFailureReason::ProviderOutputRejected,
        ),
        generation(
            GenerationTerminal::Completed,
            3,
            5,
            MessageRole::User,
            2,
            1,
            GenerationFailureReason::ProviderOutputRejected,
        ),
    ]
}
fn overflow_command() -> NormalizedMutationCommand {
    NormalizedMutationCommand::GenerateText {
        conversation_id: id("conversation"),
        expected_version: u64::MAX,
        text: "prompt".into(),
    }
}

#[test]
fn rejected_and_prohibited_are_distinct_terminal_evidence() {
    let rejected = generation(
        GenerationTerminal::Rejected,
        3,
        5,
        MessageRole::User,
        1,
        0,
        GenerationFailureReason::ProviderOutputRejected,
    );
    let prohibited = generation(
        GenerationTerminal::Prohibited,
        3,
        5,
        MessageRole::User,
        1,
        0,
        GenerationFailureReason::ProviderOutputRejected,
    );
    assert_ne!(rejected.encode().unwrap(), prohibited.encode().unwrap());
}

fn outcome_matches(
    outcome: &CanonicalMutationOutcome,
    command: &NormalizedMutationCommand,
) -> bool {
    if command_version(command) > i64::MAX as u64 {
        return outcome.correlates_to_command(command);
    }
    let directory = tempfile::tempdir().unwrap();
    let secure = runne_secure_store::test_support::DeterministicSecureStore::new([98; 32]);
    let mut store = runne_local_store::LocalStore::open_anchored(
        &directory.path().join("profile.sqlite3"),
        &secure,
        [98; 32],
    )
    .unwrap();
    let identity = runne_local_store::MutationIdentity::new(
        [1; 32],
        [2; 32],
        runne_local_store::MutationOperation::ConversationGenerateText,
        runne_local_store::MutationTargetKind::Conversation,
        id("conversation"),
        "correlation",
        command_version(command),
        [3; 32],
    )
    .unwrap();
    store
        .prepare_anchored_mutation_v7(&secure, identity.clone(), command.clone())
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity.clone(),
            runne_local_store::V7MutationTransition::Observing { timestamp: 2 },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity,
            runne_local_store::V7MutationTransition::CanonicalOutcome {
                outcome: Box::new(outcome.clone()),
                summary: "result".into(),
                timestamp: 3,
            },
        )
        .is_ok()
}

fn command_version(command: &NormalizedMutationCommand) -> u64 {
    match command {
        NormalizedMutationCommand::GenerateText {
            expected_version, ..
        } => *expected_version,
        _ => unreachable!(),
    }
}

fn generation(
    terminal: GenerationTerminal,
    stream: u64,
    task_stream: u64,
    role: MessageRole,
    user_at: u64,
    assistant_at: u64,
    reason: GenerationFailureReason,
) -> CanonicalMutationOutcome {
    let task = id("task");
    let attempt = id("attempt");
    let user = LedgerMessage {
        message_id: id("user"),
        role,
        task_run_id: task.clone(),
        attempt_id: attempt.clone(),
        text: "prompt".into(),
        committed_at: user_at,
    };
    let assistant = if terminal == GenerationTerminal::Completed {
        GenerationAssistant::Completed(LedgerMessage {
            message_id: id("assistant"),
            role: MessageRole::Assistant,
            task_run_id: task.clone(),
            attempt_id: attempt.clone(),
            text: "answer".into(),
            committed_at: assistant_at,
        })
    } else {
        GenerationAssistant::Rejected {
            reserved_message_id: id("reserved"),
            reason,
        }
    };
    CanonicalMutationOutcome::Generation {
        terminal,
        conversation_id: id("conversation"),
        task_run_id: task,
        attempt_id: attempt,
        conversation_stream_version: stream,
        task_run_stream_version: task_stream,
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
