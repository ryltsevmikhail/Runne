use runne_local_store::{
    BoundedCanonicalId, CanonicalMutationOutcome, GenerationAssistant, GenerationTerminal,
    LedgerMessage, LocalStore, MessageRole, MutationIdentity, MutationOperation,
    MutationTargetKind, NormalizedMutationCommand, V7MutationTransition,
};
use runne_secure_store::SecureStore;

pub const PROFILE: [u8; 32] = [211; 32];
pub const RUNTIME: [u8; 32] = [212; 32];
pub const PRINCIPAL: [u8; 32] = [213; 32];
pub const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000081";
pub const INPUT: &str = "RUNNE_T1_FAKE_API_KEY_7f3a9c41d2e8b605";
pub const PROJECT_CANARY: &str = "RUNNE_T1_PROJ_FILE_CANARY_8ad3e5";

#[must_use]
pub fn identity(key: &str) -> MutationIdentity {
    identity_with(key, [214; 32])
}

#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn identity_with(key: &str, semantic_digest: [u8; 32]) -> MutationIdentity {
    MutationIdentity::new(
        RUNTIME,
        PRINCIPAL,
        MutationOperation::ConversationGenerateText,
        MutationTargetKind::Conversation,
        BoundedCanonicalId::parse(CONVERSATION.as_bytes()).unwrap(),
        key,
        4,
        semantic_digest,
    )
    .unwrap()
}

#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn command() -> NormalizedMutationCommand {
    NormalizedMutationCommand::GenerateText {
        conversation_id: BoundedCanonicalId::parse(CONVERSATION.as_bytes()).unwrap(),
        expected_version: 4,
        text: INPUT.to_owned(),
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn assert_no_input_in_sqlite_family(path: &std::path::Path) {
    let canaries = [INPUT.as_bytes(), PROJECT_CANARY.as_bytes()];
    for suffix in ["", "-wal", "-shm"] {
        let candidate = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            std::path::PathBuf::from(format!("{}{suffix}", path.display()))
        };
        if let Ok(bytes) = std::fs::read(candidate) {
            for canary in canaries {
                assert!(!bytes.windows(canary.len()).any(|window| window == canary));
            }
        }
    }
}

#[allow(dead_code)]
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn outcome() -> CanonicalMutationOutcome {
    let id = |suffix: &str| {
        let hash = suffix.bytes().fold(0_u64, |hash, byte| {
            hash.wrapping_mul(16_777_619).wrapping_add(u64::from(byte))
        });
        let text = format!(
            "018f2e3a-7000-7000-8000-{:012x}",
            hash & 0x0000_ffff_ffff_ffff
        );
        BoundedCanonicalId::parse(text.as_bytes()).unwrap()
    };
    let task = id("task");
    let attempt = id("attempt");
    let user = LedgerMessage {
        message_id: BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000001").unwrap(),
        role: MessageRole::User,
        task_run_id: task.clone(),
        attempt_id: attempt.clone(),
        text: INPUT.to_owned(),
        committed_at: 1,
    };
    let assistant = LedgerMessage {
        message_id: BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000002").unwrap(),
        role: MessageRole::Assistant,
        task_run_id: task.clone(),
        attempt_id: attempt.clone(),
        text: PROJECT_CANARY.into(),
        committed_at: 2,
    };
    CanonicalMutationOutcome::Generation {
        terminal: GenerationTerminal::Completed,
        conversation_id: BoundedCanonicalId::parse(CONVERSATION.as_bytes()).unwrap(),
        task_run_id: task,
        attempt_id: attempt,
        conversation_stream_version: 6,
        task_run_stream_version: 5,
        user_message: user,
        assistant: Box::new(GenerationAssistant::Completed(assistant)),
    }
}

#[allow(dead_code)]
#[must_use]
pub fn hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String is infallible");
            output
        },
    )
}

#[allow(dead_code)]
#[must_use]
pub fn sqlite_family_snapshot(path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    ["", "-wal", "-shm"]
        .into_iter()
        .filter_map(|suffix| {
            let candidate = if suffix.is_empty() {
                path.to_path_buf()
            } else {
                std::path::PathBuf::from(format!("{}{suffix}", path.display()))
            };
            std::fs::read(candidate)
                .ok()
                .map(|bytes| (suffix.to_owned(), bytes))
        })
        .collect()
}

#[allow(dead_code, clippy::missing_panics_doc)]
pub fn install_legacy_v8_payloads(
    path: &std::path::Path,
    secure: &dyn SecureStore,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, CanonicalMutationOutcome) {
    let mut store = LocalStore::open_anchored(path, secure, PROFILE).unwrap();
    store
        .prepare_anchored_mutation_v7(secure, identity("legacy-input"), command())
        .unwrap();
    let outcome_identity = identity_with("legacy-outcome", [216; 32]);
    store
        .prepare_anchored_mutation_v7(secure, outcome_identity.clone(), command())
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            secure,
            outcome_identity.clone(),
            V7MutationTransition::Dispatching { timestamp: 1 },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            secure,
            outcome_identity.clone(),
            V7MutationTransition::Observing { timestamp: 2 },
        )
        .unwrap();
    let outcome = outcome();
    assert!(outcome.correlates_to_command(&command()));
    let logical_outcome = outcome.clone();
    let outcome_bytes = outcome.encode().unwrap();
    store
        .transition_anchored_mutation_v7(
            secure,
            outcome_identity,
            V7MutationTransition::CanonicalOutcome {
                outcome: Box::new(outcome),
                summary: "completed".into(),
                timestamp: 3,
            },
        )
        .unwrap();
    let legacy_bytes = command().encode().unwrap();
    let refs = rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT command_ref,outcome_ref FROM mutation_ledger WHERE idempotency_key='legacy-outcome'",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .unwrap();
    let sql = format!(
        "UPDATE mutation_ledger SET normalized_command=x'{}',canonical_outcome=x'{}' WHERE idempotency_key='legacy-outcome'",
        hex(&legacy_bytes),
        hex(&outcome_bytes)
    );
    runne_local_store::security_open_test_support::downgrade_to_v8_for_test(
        &mut store, secure, &sql,
    )
    .unwrap();
    drop(store);
    (legacy_bytes, refs.0, refs.1, logical_outcome)
}
