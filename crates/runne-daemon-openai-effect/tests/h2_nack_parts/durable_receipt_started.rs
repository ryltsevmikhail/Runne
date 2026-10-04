use std::sync::atomic::AtomicU8;

use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{
    ApplicationCommandContext, EventStore, IdGenerationError, IdGenerator, PrincipalId,
    ProjectWorkspaceRepository, RuntimeAuthorityId,
};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, EventId, IdempotencyKey, MessageId};
use runne_domain::message::MessageText;
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_store::project_workspace::ProjectWorkspaceStore;
use runne_store::store::StoreTransaction;

fn seed_lawful_started_text(
    path: &std::path::Path,
    identity: MainDatabaseIdentity,
) -> (ConversationId, TaskRunId, runne_domain::id::AttemptId) {
    let authority = RuntimeAuthorityId("01010101010101010101010101010101".into());
    let guard: std::sync::Arc<dyn ProhibitedContentPort> = std::sync::Arc::new(AllowContent);
    let store = StoreTransaction::open_with_connections(
        path.to_str().expect("database path"),
        open_validated_connection(path, identity).expect("started writer"),
        open_validated_reader(path, identity).expect("started reader"),
        authority.clone(),
        std::sync::Arc::clone(&guard),
    )
    .expect("started event store");
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let project_id = id("018f2e3a-7000-7000-8000-000000000061");
    let workspace_id = id("018f2e3a-7000-7000-8000-000000000062");
    repository
        .create_project(
            "principal-1",
            command(0x31),
            &key("lawful-start-project"),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Provider start fixture".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            "principal-1",
            command(0x32),
            &key("lawful-start-workspace"),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Provider start fixture".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .open_workspace(
            "principal-1",
            command(0x33),
            &key("lawful-start-open"),
            workspace_id,
            1,
        )
        .unwrap();
    let conversation_id = id("018f2e3a-7000-7000-8000-000000000006");
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &context(0x34, "lawful-start-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: command(0x34),
                idempotency_key: key("lawful-start-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let started =
        ConversationTextService::new(store.clone(), StartedIds::default(), authority, guard)
            .begin(
                &context(0x35, "lawful-start-text"),
                BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("lawful provider start").unwrap(),
                },
            )
            .unwrap();
    store
        .load_task_run(started.taskrun_id)
        .expect("durable started TaskRun");
    (
        started.conversation_id,
        started.taskrun_id,
        started.attempt_id,
    )
}

fn read_semantic_digest(path: &std::path::Path, attempt_id: &[u8; 16]) -> [u8; 32] {
    rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("read exact admitted semantic digest")
        .query_row(
            "SELECT semantic_digest FROM provider_execution_admissions WHERE dispatch_attempt_id=?1",
            [attempt_id.as_slice()],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
            },
        )
        .expect("persisted admission semantic digest")
}

struct AllowContent;
impl ProhibitedContentPort for AllowContent {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

#[derive(Default)]
struct StartedIds {
    message: AtomicU8,
    event: AtomicU8,
}
impl IdGenerator for StartedIds {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        Ok(id("018f2e3a-7000-7000-8000-000000000007"))
    }
    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
        Ok(id("018f2e3a-7000-7000-8000-000000000006"))
    }
    fn next_attempt_id(&self) -> Result<runne_domain::id::AttemptId, IdGenerationError> {
        Ok(id("018f2e3a-7000-7000-8000-000000000008"))
    }
    fn next_message_id(&self) -> Result<MessageId, IdGenerationError> {
        let suffix = 0x70 + self.message.fetch_add(1, Ordering::SeqCst);
        Ok(uuid7(0xA0, 0, u32::from(suffix)))
    }
    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        let count = u8::try_from(count).map_err(|_| IdGenerationError::Exhausted)?;
        let start = self.event.fetch_add(count, Ordering::SeqCst);
        Ok((0..count)
            .map(|offset| uuid7(0xE0, 0, u32::from(0x80 + start + offset)))
            .collect())
    }
}

fn context(value: u8, name: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command(value),
        idempotency_key: key(name),
        principal_id: PrincipalId("principal-1".into()),
        actor: Actor::new("provider-effect-test").unwrap(),
    }
}
fn command(value: u8) -> CommandId {
    uuid7(0xC0, 0, u32::from(value))
}
fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value.to_owned()).unwrap()
}
fn id<T>(value: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("deterministic UUIDv7 fixture ID")
}

fn uuid7<T>(kind: u8, discriminator: u8, value: u32) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    id(&format!(
        "018f2e3a-7000-7000-8000-{kind:02x}{discriminator:02x}{value:08x}"
    ))
}
