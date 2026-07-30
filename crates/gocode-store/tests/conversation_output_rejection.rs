use std::sync::Arc;

use gocode_api::CreateConversationInput;
use gocode_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::ConversationTextService;
use gocode_application::ports::{
    ApplicationCommandContext, ConversationRepository, EventStore, PrincipalId, RuntimeAuthorityId,
    TextGenerationPhase,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_domain::conversation::{Conversation, GenerationFailureReason};
use gocode_domain::event::Actor;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use gocode_domain::message::MessageText;
use gocode_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use gocode_store::store::StoreTransaction;

struct AllowGuard;

impl ProhibitedContentPort for AllowGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

fn context(command_id: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command_id.parse::<CommandId>().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("store-test").unwrap(),
    }
}

#[test]
fn rejected_provider_output_is_terminal_idempotent_and_creates_no_assistant_message() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory
        .path()
        .join("output-rejection.sqlite")
        .to_str()
        .unwrap()
        .to_owned();
    let authority = RuntimeAuthorityId("output-rejection-test".into());
    let store = StoreTransaction::open(&database_path, authority.clone()).unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000002".parse().unwrap();
    let create_context = context(
        "018f2e3a-7000-7000-8000-000000000003",
        "create-conversation",
    );
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
            },
        )
        .unwrap();

    let generation_context = context("018f2e3a-7000-7000-8000-000000000004", "generate-text");
    let service = ConversationTextService::new(
        store.clone(),
        store.clone(),
        authority,
        Arc::new(AllowGuard),
    );
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("hello").unwrap(),
    };
    let started = service
        .begin(&generation_context, original.clone())
        .unwrap();
    assert_eq!(started.phase, TextGenerationPhase::Started);
    let rejected_input = FinishConversationTextInput {
        original,
        started: started.clone(),
        completion: ConversationTextCompletion::Rejected {
            reason: GenerationFailureReason::ProviderOutputRejected,
        },
    };

    let rejected = service
        .finish(&generation_context, rejected_input.clone())
        .unwrap();
    let duplicate = service.finish(&generation_context, rejected_input).unwrap();

    assert_eq!(rejected, duplicate);
    assert_eq!(rejected.phase, TextGenerationPhase::Rejected);
    assert_eq!(rejected.conversation_version, 3);
    assert_eq!(rejected.taskrun_version, 5);

    let conversation_stream = store.load_conversation(conversation_id).unwrap();
    assert_eq!(conversation_stream.current_version, 3);
    let conversation = Conversation::replay(&conversation_stream.events).unwrap();
    assert_eq!(conversation.messages().len(), 1);
    assert_eq!(conversation.active_generation(), None);

    let taskrun_stream = store.load_task_run(rejected.taskrun_id).unwrap();
    assert_eq!(taskrun_stream.current_version, 5);
    assert!(matches!(
        taskrun_stream.events.last().unwrap().payload(),
        TaskRunEvent::TaskRunFailed { reason } if reason == "provider_output_rejected"
    ));
    let taskrun = TaskRun::replay(&taskrun_stream.events).unwrap();
    assert_eq!(taskrun.state(), TaskRunState::Failed);
    assert_eq!(taskrun.active_attempt(), None);
}
