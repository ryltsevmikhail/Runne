use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::project_workspace::ProjectWorkspaceStore;
use crate::store::StoreTransaction;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::ProjectWorkspaceRepository;
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, EventStore, EventStoreError,
    IdGenerationError, IdGenerator, PrincipalId, RuntimeAuthorityId,
};
use runne_domain::event::Actor;
use runne_domain::id::{
    AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, MessageId, ProjectId, TaskRunId,
    WorkspaceId,
};
use runne_domain::message::MessageText;
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_security::SecretBroker;

#[path = "canonical_started_additional.rs"]
mod additional;
pub(super) use additional::seed_distinct;

pub(super) fn seed(path: &Path, discriminator: u8) -> (ConversationId, TaskRunId, AttemptId) {
    let authority = RuntimeAuthorityId("01010101010101010101010101010101".into());
    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let writer = super::authority_test_support::configured_connection(path);
    let reader = crate::schema::reopen_managed_connection_validated(
        path,
        crate::schema::ConnectionMode::Reader,
        |_| Ok(()),
    )
    .unwrap();
    let store = StoreTransaction::open_with_connections(
        path.to_str().unwrap(),
        writer,
        reader,
        authority.clone(),
        guard.clone(),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000006"
        .parse()
        .expect("deterministic UUIDv7 conversation ID");
    let taskrun_id: TaskRunId = "018f2e3a-7000-7000-8000-000000000007"
        .parse()
        .expect("deterministic UUIDv7 TaskRun ID");
    let attempt_id: AttemptId = "018f2e3a-7000-7000-8000-000000000008"
        .parse()
        .expect("deterministic UUIDv7 attempt ID");
    match store.load_task_run(taskrun_id) {
        Ok(_) => {
            verify_existing(&store, conversation_id, taskrun_id, attempt_id);
            return (conversation_id, taskrun_id, attempt_id);
        }
        Err(EventStoreError::NotFound) => {}
        Err(error) => panic!("existing provider TaskRun is not readable: {error:?}"),
    }
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let principal = "principal-1";
    let project_id: ProjectId = "018f2e3a-7000-7000-8000-000000000061"
        .parse()
        .expect("deterministic UUIDv7 project ID");
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000062"
        .parse()
        .expect("deterministic UUIDv7 workspace ID");
    repository
        .create_project(
            principal,
            command(0x31, discriminator),
            &key("provider-start-project", discriminator),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Provider start test".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            principal,
            command(0x32, discriminator),
            &key("provider-start-workspace", discriminator),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Provider start workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .open_workspace(
            principal,
            command(0x33, discriminator),
            &key("provider-start-open", discriminator),
            workspace_id,
            1,
        )
        .unwrap();

    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &context(0x34, discriminator, "provider-start-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: command(0x34, discriminator),
                idempotency_key: key("provider-start-conversation", discriminator),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let text = ConversationTextService::new(store.clone(), FixedIds::default(), authority, guard);
    text.begin(
        &context(0x35, discriminator, "provider-start-text"),
        BeginConversationTextInput {
            conversation_id,
            expected_version: 1,
            text: MessageText::new("canonical provider start").unwrap(),
        },
    )
    .unwrap();
    drop(store);
    (conversation_id, taskrun_id, attempt_id)
}

fn verify_existing(
    store: &StoreTransaction,
    conversation_id: ConversationId,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) {
    let taskrun = store
        .load_task_run(taskrun_id)
        .expect("canonical provider TaskRun exists");
    let expected = [
        runne_domain::task_run::TaskRunEvent::TaskRunCreated,
        runne_domain::task_run::TaskRunEvent::TaskRunQueued,
        runne_domain::task_run::TaskRunEvent::TaskRunAdmitted,
        runne_domain::task_run::TaskRunEvent::AttemptStarted { attempt_id },
    ];
    assert!(taskrun.events.len() >= expected.len());
    assert!(
        taskrun
            .events
            .iter()
            .zip(expected.iter())
            .all(|(event, expected)| event.payload() == expected)
    );
    let conversation = store
        .load_conversation(conversation_id)
        .expect("canonical conversation exists");
    assert!(matches!(
        conversation
            .events
            .iter()
            .find_map(|event| match event.payload() {
                runne_domain::conversation::ConversationEvent::UserMessageAppended {
                    taskrun_id: bound_taskrun,
                    attempt_id: bound_attempt,
                    text,
                    ..
                } if *bound_taskrun == taskrun_id
                    && *bound_attempt == attempt_id
                    && text.as_str() == "canonical provider start" =>
                    Some(()),
                _ => None,
            }),
        Some(())
    ));
}

#[derive(Default)]
struct FixedIds {
    message: AtomicU8,
    event: AtomicU8,
}

impl IdGenerator for FixedIds {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        Ok("018f2e3a-7000-7000-8000-000000000007"
            .parse()
            .expect("deterministic UUIDv7 TaskRun ID"))
    }

    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
        Ok("018f2e3a-7000-7000-8000-000000000006"
            .parse()
            .expect("deterministic UUIDv7 conversation ID"))
    }

    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok("018f2e3a-7000-7000-8000-000000000008"
            .parse()
            .expect("deterministic UUIDv7 attempt ID"))
    }

    fn next_message_id(&self) -> Result<MessageId, IdGenerationError> {
        let value = 0x70 + self.message.fetch_add(1, Ordering::SeqCst);
        Ok(uuid7_id(0xA0, 0, u32::from(value)))
    }

    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        let count = u8::try_from(count).map_err(|_| IdGenerationError::Exhausted)?;
        let start = self.event.fetch_add(count, Ordering::SeqCst);
        Ok((0..count)
            .map(|offset| uuid7_id(0xE0, 0, u32::from(0x80 + start + offset)))
            .collect())
    }
}

fn context(byte: u8, discriminator: u8, name: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command(byte, discriminator),
        idempotency_key: key(name, discriminator),
        principal_id: PrincipalId("principal-1".into()),
        actor: Actor::new("provider-start-test").unwrap(),
    }
}

fn command(byte: u8, discriminator: u8) -> CommandId {
    uuid7_id(0xC0, discriminator, u32::from(byte ^ discriminator))
}

fn uuid7_id<T>(kind: u8, discriminator: u8, value: u32) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    format!("018f2e3a-7000-7000-8000-{kind:02x}{discriminator:02x}{value:08x}")
        .parse()
        .expect("deterministic UUIDv7 fixture ID")
}

fn key(name: &str, discriminator: u8) -> IdempotencyKey {
    IdempotencyKey::new(format!("{name}-{discriminator}")).unwrap()
}
