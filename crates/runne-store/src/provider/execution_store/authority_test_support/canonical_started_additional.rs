use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::store::StoreTransaction;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{EventStore, EventStoreError, RuntimeAuthorityId};
use runne_domain::id::{AttemptId, ConversationId, EventId, MessageId, TaskRunId};
use runne_domain::message::MessageText;
use runne_security::SecretBroker;

pub(super) fn seed_additional(
    path: &Path,
    discriminator: u8,
    conversation_id: ConversationId,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) -> (ConversationId, TaskRunId, AttemptId) {
    super::seed(path, discriminator);
    let authority = RuntimeAuthorityId("01010101010101010101010101010101".into());
    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let writer = super::super::authority_test_support::configured_connection(path);
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
    match store.load_task_run(taskrun_id) {
        Ok(_) => {
            super::verify_existing(&store, conversation_id, taskrun_id, attempt_id);
            return (conversation_id, taskrun_id, attempt_id);
        }
        Err(EventStoreError::NotFound) => {}
        Err(error) => panic!("additional canonical TaskRun is unreadable: {error:?}"),
    }
    let workspace_id: runne_domain::id::WorkspaceId = "018f2e3a-7000-7000-8000-000000000062"
        .parse()
        .expect("shared canonical workspace ID");
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &super::context(
                0x36,
                discriminator,
                "provider-start-additional-conversation",
            ),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: super::command(0x36, discriminator),
                idempotency_key: super::key(
                    "provider-start-additional-conversation",
                    discriminator,
                ),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    ConversationTextService::new(
        store.clone(),
        AdditionalIds::new(conversation_id, taskrun_id, attempt_id, discriminator),
        authority,
        guard,
    )
    .begin(
        &super::context(0x37, discriminator, "provider-start-additional-text"),
        BeginConversationTextInput {
            conversation_id,
            expected_version: 1,
            text: MessageText::new("canonical provider start").unwrap(),
        },
    )
    .unwrap();
    super::verify_existing(&store, conversation_id, taskrun_id, attempt_id);
    (conversation_id, taskrun_id, attempt_id)
}

pub(in crate::provider::execution_store) fn seed_distinct(
    path: &Path,
    discriminator: u8,
) -> (ConversationId, TaskRunId, AttemptId) {
    seed_additional(
        path,
        discriminator,
        super::uuid7_id(0xA1, discriminator, u32::from(discriminator)),
        super::uuid7_id(0xA2, discriminator, u32::from(discriminator)),
        super::uuid7_id(0xA3, discriminator, u32::from(discriminator)),
    )
}

struct AdditionalIds {
    message: AtomicU8,
    event: AtomicU8,
    conversation_id: ConversationId,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    discriminator: u8,
}

impl AdditionalIds {
    fn new(
        conversation_id: ConversationId,
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        discriminator: u8,
    ) -> Self {
        Self {
            message: AtomicU8::default(),
            event: AtomicU8::default(),
            conversation_id,
            taskrun_id,
            attempt_id,
            discriminator,
        }
    }
}

impl runne_application::ports::IdGenerator for AdditionalIds {
    fn next_taskrun_id(&self) -> Result<TaskRunId, runne_application::ports::IdGenerationError> {
        Ok(self.taskrun_id)
    }

    fn next_conversation_id(
        &self,
    ) -> Result<ConversationId, runne_application::ports::IdGenerationError> {
        Ok(self.conversation_id)
    }

    fn next_attempt_id(&self) -> Result<AttemptId, runne_application::ports::IdGenerationError> {
        Ok(self.attempt_id)
    }

    fn next_message_id(&self) -> Result<MessageId, runne_application::ports::IdGenerationError> {
        let value = 0x70 + self.message.fetch_add(1, Ordering::SeqCst);
        Ok(super::uuid7_id(0xA0, self.discriminator, u32::from(value)))
    }

    fn next_event_ids(
        &self,
        count: usize,
    ) -> Result<Vec<EventId>, runne_application::ports::IdGenerationError> {
        let count = u8::try_from(count)
            .map_err(|_| runne_application::ports::IdGenerationError::Exhausted)?;
        let start = self.event.fetch_add(count, Ordering::SeqCst);
        Ok((0..count)
            .map(|offset| {
                super::uuid7_id(0xE0, self.discriminator, u32::from(0x80 + start + offset))
            })
            .collect())
    }
}
