use super::*;
use runne_api::CreateConversationInput;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{
    ApplicationCommandContext, PrincipalId, ProjectWorkspaceRepository, RuntimeAuthorityId,
    TextGenerationPhase, TextGenerationReceipt,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::event::Actor;
use runne_domain::id::{
    AttemptId, ConversationId, IdempotencyKey, MessageId, ProjectId, TaskRunId, WorkspaceId,
};
use runne_domain::message::MessageText;
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_security::SecretBroker;
use runne_store::ProjectWorkspaceStore;

mod manifest_negatives;

fn source_pinned_command_vector() -> CanonicalProviderExecutionJob {
    CanonicalProviderExecutionJob {
        context: ApplicationCommandContext {
            command_id: "018f2e3a-7000-7000-8000-000000000804".parse().unwrap(),
            idempotency_key: IdempotencyKey::new("source-pinned-provider-vector").unwrap(),
            principal_id: PrincipalId("local-owner".into()),
            actor: Actor::new("test").unwrap(),
        },
        original: BeginConversationTextInput {
            conversation_id: ConversationId::from_bytes([1; 16]),
            expected_version: 1,
            text: MessageText::new("fixture input").unwrap(),
        },
        started: TextGenerationReceipt {
            phase: TextGenerationPhase::Started,
            conversation_id: ConversationId::from_bytes([1; 16]),
            workspace_id: WorkspaceId::from_bytes([2; 16]),
            taskrun_id: TaskRunId::from_bytes([3; 16]),
            attempt_id: AttemptId::from_bytes([4; 16]),
            user_message_id: MessageId::from_bytes([5; 16]),
            assistant_message_id: MessageId::from_bytes([6; 16]),
            conversation_version: 2,
            taskrun_version: 4,
        },
    }
}

#[test]
fn remote_effect_idempotency_key_matches_the_pre_rename_command_vector() {
    assert_eq!(
        provider_idempotency_key(&source_pinned_command_vector()),
        "gocode-provider-c436f15d42859a67270a2f39ff1c8508"
    );
}

#[test]
fn admission_errors_preserve_pre_effect_and_post_claim_stages() {
    assert_eq!(
        map_admission_error(ProviderAdmissionError::ApprovalDenied),
        CanonicalProviderExecutionError::RejectedBeforeEffect
    );
    assert_eq!(
        map_admission_error(ProviderAdmissionError::PostClaimUncertain),
        CanonicalProviderExecutionError::Uncertain
    );
    assert_eq!(
        map_admission_error(ProviderAdmissionError::RepositoryFailure),
        CanonicalProviderExecutionError::Unavailable
    );
}

#[test]
fn adapter_stream_and_terminal_application_failures_are_post_effect_uncertain() {
    assert_eq!(
        map_execution_error(RuntimeProviderExecutionError::AdapterStreamUnavailable),
        CanonicalProviderExecutionError::Uncertain
    );
    assert_eq!(
        map_execution_error(RuntimeProviderExecutionError::ApplicationUnavailable),
        CanonicalProviderExecutionError::Uncertain
    );
}

#[test]
fn duplicate_nonterminal_states_require_uncertain_reconciliation() {
    for state in [
        runne_provider::ProviderRepositoryState::Dispatching,
        runne_provider::ProviderRepositoryState::Streaming,
        runne_provider::ProviderRepositoryState::TerminalPendingCommit,
        runne_provider::ProviderRepositoryState::Uncertain,
    ] {
        assert_eq!(
            map_existing_state(state),
            CanonicalProviderExecutionError::Uncertain
        );
    }
}

/// Durable identity of one seeded text-path conversation, held without any
/// open store connection so tampering and reopen tests own the file.
struct TextPathSeed {
    context: ApplicationCommandContext,
    original: BeginConversationTextInput,
    started: TextGenerationReceipt,
}

fn text_path_database(tag: &str) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join(format!("{tag}.sqlite"));
    (directory, path.to_str().unwrap().to_owned())
}

fn text_path_guard() -> std::sync::Arc<dyn ProhibitedContentPort> {
    std::sync::Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn text_path_context(suffix: u64, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-{suffix:012}")
            .parse()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("d13-projection").unwrap(),
    }
}

/// Builds a real project/workspace/conversation and one started begin on an
/// already-open store; every durable id and command is derived from
/// `suffix`, so several seeds may share one database.
fn seed_started_conversation(
    store: &StoreTransaction,
    authority: RuntimeAuthorityId,
    suffix: u16,
    text: &str,
) -> TextPathSeed {
    let projects = ProjectWorkspaceStore::from_store(store.clone());
    let conversation_id: ConversationId = format!("018f2e3a-7000-7000-8001-{suffix:012}")
        .parse()
        .unwrap();
    let workspace_id: WorkspaceId = format!("018f2e3a-7000-7000-8002-{:012}", 200 + suffix as u64)
        .parse()
        .unwrap();
    let project_id: ProjectId = format!("018f2e3a-7000-7000-8002-{:012}", 100 + suffix as u64)
        .parse()
        .unwrap();
    projects
        .create_project(
            "local-owner",
            format!("018f2e3a-7000-7000-8002-{:012}", 300 + suffix as u64)
                .parse()
                .unwrap(),
            &IdempotencyKey::new(format!("create-project-{suffix}")).unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    projects
        .create_workspace(
            "local-owner",
            format!("018f2e3a-7000-7000-8002-{:012}", 400 + suffix as u64)
                .parse()
                .unwrap(),
            &IdempotencyKey::new(format!("create-workspace-{suffix}")).unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    let create_context = text_path_context(
        500 + u64::from(suffix),
        &format!("create-conversation-{suffix}"),
    );
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let service =
        ConversationTextService::new(store.clone(), store.clone(), authority, text_path_guard());
    let context = text_path_context(600 + u64::from(suffix), &format!("generate-text-{suffix}"));
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new(text).unwrap(),
    };
    let started = service.begin(&context, original.clone()).unwrap();
    assert_eq!(started.phase, TextGenerationPhase::Started);
    TextPathSeed {
        context,
        original,
        started,
    }
}

fn text_path_profile() -> OpenAiTextProviderProfile {
    OpenAiTextProviderProfile::new(
        runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
            "../../../../../../docs/profiles/openai-responses-text-v1.json"
        ))
        .unwrap(),
    )
}

fn project_text_path(
    store: &StoreTransaction,
    seed: &TextPathSeed,
) -> Result<ProviderCall, CanonicalProviderExecutionError> {
    let job = CanonicalProviderExecutionJob {
        context: seed.context.clone(),
        original: seed.original.clone(),
        started: seed.started.clone(),
    };
    project_call(
        store,
        &job,
        &text_path_profile(),
        "openai",
        "gpt-4o-mini",
        "2024-07-18",
    )
}

/// Applies one tampering statement bound to the seeded conversation id and
/// reopens the store; the tamper connection is closed inside this call.
fn reopen_after_tamper(
    database_path: &str,
    authority: RuntimeAuthorityId,
    conversation_id: ConversationId,
    sql: &str,
) -> StoreTransaction {
    rusqlite::Connection::open(database_path)
        .unwrap()
        .execute(sql, rusqlite::params![conversation_id.as_bytes()])
        .unwrap();
    StoreTransaction::open(database_path, authority, text_path_guard()).unwrap()
}
