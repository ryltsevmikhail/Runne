use std::sync::Arc;

use gocode_api::{
    ApiPrincipalId, CanonicalMessageText, CommandReconciliationContext,
    CommandReconciliationWitness, CreateConversationInput, ProjectWorkspaceDisplayNameInput,
};
use gocode_application::command_reconciliation::{
    CommandReconciliationEvidence, CommandReconciliationRepository,
    CommandReconciliationRepositoryError,
};
use gocode_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::ConversationTextService;
use gocode_application::ports::{
    ApplicationCommandContext, ProjectWorkspaceRepository, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_domain::conversation::GenerationFailureReason;
use gocode_domain::event::Actor;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, ProjectId, WorkspaceId};
use gocode_domain::message::MessageText;
use gocode_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use gocode_security::SecretBroker;
use gocode_store::ProjectWorkspaceStore;

#[path = "command_reconciliation/conversation.rs"]
mod conversation_cases;
#[path = "command_reconciliation/negative.rs"]
mod negative;
#[path = "command_reconciliation/project_workspace.rs"]
mod project_workspace;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

fn context(command: CommandId) -> CommandReconciliationContext {
    CommandReconciliationContext::new(
        command,
        IdempotencyKey::new("key").unwrap(),
        ApiPrincipalId::new("owner").unwrap(),
    )
}
fn project() -> ProjectId {
    "018f47a2-4f8c-7b52-8c35-7a3a14c2d902".parse().unwrap()
}
fn workspace() -> WorkspaceId {
    "018f47a2-4f8c-7b52-8c35-7a3a14c2d903".parse().unwrap()
}
fn conversation() -> ConversationId {
    "018f47a2-4f8c-7b52-8c35-7a3a14c2d904".parse().unwrap()
}
fn application_context(command: CommandId, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command,
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: gocode_application::ports::PrincipalId("owner".into()),
        actor: Actor::new("test").unwrap(),
    }
}
fn guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

struct Fixture {
    _file: validated_reopen::ValidatedTestDatabase,
    store: gocode_store::store::StoreTransaction,
    repository: ProjectWorkspaceStore,
}
impl Fixture {
    fn new(name: &str) -> Self {
        let file = validated_reopen::ValidatedTestDatabase::new(name);
        let (store, _) = validated_reopen::initialize_store(
            file.path(),
            RuntimeAuthorityId("authority".into()),
            guard(),
        )
        .unwrap();
        Self {
            _file: file,
            repository: ProjectWorkspaceStore::from_store(store.clone()),
            store,
        }
    }
    fn project_workspace(&self) {
        self.repository
            .create_project(
                "owner",
                command(1),
                &IdempotencyKey::new("project").unwrap(),
                Project::create(
                    project(),
                    ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
                ),
            )
            .unwrap();
        self.repository
            .create_workspace(
                "owner",
                command(2),
                &IdempotencyKey::new("workspace").unwrap(),
                Workspace::create(
                    workspace(),
                    project(),
                    ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
                ),
            )
            .unwrap();
    }
    fn conversation(&self, command: CommandId, key: &str) {
        self.project_workspace();
        let command_context = application_context(command, key);
        ConversationService::new(
            self.store.clone(),
            self.store.clone(),
            RuntimeAuthorityId("authority".into()),
        )
        .create_from_application(
            &command_context,
            CreateConversationInput {
                conversation_id: conversation(),
                workspace_id: workspace(),
                command_id: command_context.command_id,
                idempotency_key: command_context.idempotency_key.clone(),
            },
        )
        .unwrap();
    }
}
fn command(tail: u8) -> CommandId {
    format!("018f47a2-4f8c-7b52-8c35-7a3a14c3{tail:04x}")
        .parse()
        .unwrap()
}

#[test]
fn project_receipt_and_exact_absence_are_observed_without_writes() {
    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let file = validated_reopen::ValidatedTestDatabase::new("command-reconciliation");
    let (store, _) = validated_reopen::initialize_store(
        file.path(),
        RuntimeAuthorityId("authority".into()),
        guard,
    )
    .unwrap();
    let repository = ProjectWorkspaceStore::from_store(store);
    let command: CommandId = "018f47a2-4f8c-7b52-8c35-7a3a14c2d901".parse().unwrap();
    let witness = CommandReconciliationWitness::create_project(
        project(),
        ProjectWorkspaceDisplayNameInput::new("Project".into()).unwrap(),
    );
    assert_eq!(
        repository.reconcile_command(&context(command), &witness),
        Ok(CommandReconciliationEvidence::NotCommitted)
    );
    repository
        .create_project(
            "owner",
            command,
            &IdempotencyKey::new("key").unwrap(),
            Project::create(
                project(),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    assert!(matches!(
        repository.reconcile_command(&context(command), &witness),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));
}

#[test]
fn project_workspace_outcomes_and_absences_use_durable_mutation_receipts() {
    let fixture = Fixture::new("command-reconciliation-project-workspace");
    let create = CommandReconciliationWitness::create_project(
        project(),
        ProjectWorkspaceDisplayNameInput::new("Project".into()).unwrap(),
    );
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&context(command(3)), &create),
        Ok(CommandReconciliationEvidence::NotCommitted)
    );
    fixture
        .repository
        .create_project(
            "owner",
            command(3),
            &IdempotencyKey::new("key").unwrap(),
            Project::create(
                project(),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(command(3)), &create),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));
}

#[test]
fn conversation_and_text_outcomes_follow_durable_receipts() {
    let fixture = Fixture::new("command-reconciliation-conversation-text");
    let create_command = command(4);
    fixture.conversation(create_command, "key");
    let create = CommandReconciliationWitness::create_conversation(conversation(), workspace());
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(create_command), &create),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));

    let generate_command = command(5);
    let generate_context = application_context(generate_command, "key");
    let text = MessageText::new("hello").unwrap();
    let service = ConversationTextService::new(
        fixture.store.clone(),
        fixture.store.clone(),
        RuntimeAuthorityId("authority".into()),
        guard(),
    );
    let started = service
        .begin(
            &generate_context,
            BeginConversationTextInput {
                conversation_id: conversation(),
                expected_version: 1,
                text: text.clone(),
            },
        )
        .unwrap();
    let witness = CommandReconciliationWitness::generate_conversation_text(
        conversation(),
        1,
        CanonicalMessageText::new("hello").unwrap(),
    );
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&context(generate_command), &witness),
        Ok(CommandReconciliationEvidence::TextGenerationStarted)
    );
    service
        .finish(
            &generate_context,
            FinishConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id: conversation(),
                    expected_version: 1,
                    text,
                },
                started,
                completion: ConversationTextCompletion::Rejected {
                    reason: GenerationFailureReason::ProviderOutputRejected,
                },
            },
        )
        .unwrap();
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(generate_command), &witness),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));
}

#[test]
fn changed_reconciliation_identity_is_conflict_without_an_outcome() {
    let fixture = Fixture::new("command-reconciliation-conflict");
    let command = command(6);
    fixture
        .repository
        .create_project(
            "owner",
            command,
            &IdempotencyKey::new("key").unwrap(),
            Project::create(
                project(),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    let changed = CommandReconciliationWitness::create_project(
        project(),
        ProjectWorkspaceDisplayNameInput::new("Changed".into()).unwrap(),
    );
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&context(command), &changed),
        Err(CommandReconciliationRepositoryError::Conflict)
    );
}
