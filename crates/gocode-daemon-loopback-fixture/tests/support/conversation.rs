use gocode_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CanonicalReplayEvent, CanonicalReplayPayload,
    CommandIdentity, ConversationMessageRole, ConversationMessages, CreateConversationRequest,
    CreateProjectRequest, CreateWorkspaceRequest, GenerateTextRequest, ReplayAggregateKind,
    ReplayDeliveryDisposition, ReplayIdentityTracker, ReplayScope, RuntimeApiErrorKind,
};

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000801";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-000000000800";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000802";
const PROJECT_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000805";
const WORKSPACE_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000806";
const CREATE_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000803";
const GENERATE_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000804";
const PROJECT_IDEMPOTENCY_KEY: &str = "fixture-project-idempotency-v1";
const WORKSPACE_IDEMPOTENCY_KEY: &str = "fixture-workspace-idempotency-v1";
const CREATE_IDEMPOTENCY_KEY: &str = "fixture-create-idempotency-v1";
const GENERATE_IDEMPOTENCY_KEY: &str = "fixture-generate-idempotency-v1";
const USER_TEXT: &str = "fixture input";
const ASSISTANT_TEXT: &str = "fixture response";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedReplayEvent {
    pub event: CanonicalReplayEvent,
    pub cursor: String,
    pub digest: String,
    pub disposition: ReplayDeliveryDisposition,
}

pub struct ConversationExpectation {
    pub conversation_id: CanonicalId,
    pub workspace_id: CanonicalId,
    pub create_command_id: CanonicalId,
    pub generate_command_id: CanonicalId,
    pub timeline: ConversationMessages,
    pub task_run_id: CanonicalId,
    pub attempt_id: CanonicalId,
    pub replay_events: Vec<PersistedReplayEvent>,
    #[allow(dead_code)]
    pub last_cursor: String,
    #[allow(dead_code)]
    pub replay_tracker: ReplayIdentityTracker,
}

impl ConversationExpectation {
    pub fn assert_process_one(&self) {
        assert_eq!(self.timeline.conversation_id, self.conversation_id);
        assert_eq!(self.create_command_id, id(CREATE_COMMAND_ID));
        assert_eq!(self.generate_command_id, id(GENERATE_COMMAND_ID));
        assert_eq!(self.timeline.stream_version, 3);
        assert_eq!(self.timeline.messages.len(), 2);
        let [user, assistant] = self.timeline.messages.as_slice() else {
            panic!("exact user and assistant timeline");
        };
        assert_eq!(user.role, ConversationMessageRole::User);
        assert_eq!(user.text, USER_TEXT);
        assert_eq!(assistant.role, ConversationMessageRole::Assistant);
        assert_eq!(assistant.text, ASSISTANT_TEXT);
        assert_ne!(user.message_id, assistant.message_id);
        assert_eq!(user.task_run_id, self.task_run_id);
        assert_eq!(assistant.task_run_id, self.task_run_id);
        assert_eq!(user.attempt_id, self.attempt_id);
        assert_eq!(assistant.attempt_id, self.attempt_id);
        assert_ne!(
            self.task_run_id.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_ne!(
            self.attempt_id.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(self.replay_events.len(), 3);
        assert!(
            self.replay_events
                .iter()
                .all(|event| event.disposition == ReplayDeliveryDisposition::New)
        );
        assert_replay_matches_timeline(&self.replay_events, self);
    }
}

pub async fn send_canonical_conversation(
    client: &AuthenticatedRuntimeClient,
) -> ConversationExpectation {
    let conversation_id = id(CONVERSATION_ID);
    let project_id = id(PROJECT_ID);
    let workspace_id = id(WORKSPACE_ID);
    seed_workspace(client, project_id, workspace_id).await;
    let create_command_id = id(CREATE_COMMAND_ID);
    let generate_command_id = id(GENERATE_COMMAND_ID);
    let created = client
        .create_conversation(CreateConversationRequest::new(
            identity(create_command_id, CREATE_IDEMPOTENCY_KEY),
            conversation_id,
            workspace_id,
        ))
        .await
        .expect("create canonical Conversation");
    assert_eq!(created.conversation_id, conversation_id);
    assert_eq!(created.workspace_id, workspace_id);
    assert_eq!(created.stream_version, 1);
    let error = client
        .generate_text(
            GenerateTextRequest::new(
                identity(generate_command_id, GENERATE_IDEMPOTENCY_KEY),
                conversation_id,
                1,
                USER_TEXT,
            )
            .expect("canonical generation request"),
        )
        .await
        .expect_err("fixture ACK fault must project as an invalid response");
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
    let timeline = client
        .list_messages(conversation_id)
        .await
        .expect("committed Conversation remains readable after failed ACK");
    let [user, assistant] = timeline.messages.as_slice() else {
        panic!("committed canonical exchange");
    };
    let tracker = ReplayIdentityTracker::new();
    let replay_events = replay_from(client, conversation_id, None, tracker.clone()).await;
    let last_cursor = replay_events
        .last()
        .expect("persisted replay event")
        .cursor
        .clone();
    ConversationExpectation {
        conversation_id,
        workspace_id,
        create_command_id,
        generate_command_id,
        task_run_id: user.task_run_id,
        attempt_id: assistant.attempt_id,
        timeline,
        replay_events,
        last_cursor,
        replay_tracker: tracker,
    }
}

async fn seed_workspace(
    client: &AuthenticatedRuntimeClient,
    project_id: CanonicalId,
    workspace_id: CanonicalId,
) {
    let project = client
        .create_project(
            CreateProjectRequest::new(
                identity(id(PROJECT_COMMAND_ID), PROJECT_IDEMPOTENCY_KEY),
                project_id,
                "Fixture project",
            )
            .expect("canonical Project request"),
        )
        .await
        .expect("create canonical Project");
    assert_eq!(project.project_id(), project_id);
    assert_eq!(project.new_version(), 1);
    let workspace = client
        .create_workspace(
            CreateWorkspaceRequest::new(
                identity(id(WORKSPACE_COMMAND_ID), WORKSPACE_IDEMPOTENCY_KEY),
                project_id,
                workspace_id,
                "Fixture workspace",
            )
            .expect("canonical Workspace request"),
        )
        .await
        .expect("create canonical Workspace");
    assert_eq!(workspace.workspace_id(), workspace_id);
    assert_eq!(workspace.new_version(), 1);
}

pub async fn replay_from(
    client: &AuthenticatedRuntimeClient,
    conversation_id: CanonicalId,
    from_cursor: Option<&str>,
    tracker: ReplayIdentityTracker,
) -> Vec<PersistedReplayEvent> {
    let mut replay_events = Vec::new();
    let live = client
        .catch_up_from_persisted_cursor(
            ReplayScope::new(ReplayAggregateKind::Conversation, conversation_id),
            from_cursor,
            tracker,
            |delivery| {
                let persisted = delivery.persist_with(|handoff| PersistedReplayEvent {
                    event: delivery.event().clone(),
                    cursor: handoff.cursor_value().to_owned(),
                    digest: handoff.event_digest().to_owned(),
                    disposition: delivery.disposition(),
                });
                replay_events.push(persisted);
                Ok::<(), ()>(())
            },
            |_| {},
        )
        .await
        .expect("authoritative conversation replay");
    drop(live);
    replay_events
}

fn assert_replay_matches_timeline(
    events: &[PersistedReplayEvent],
    expectation: &ConversationExpectation,
) {
    let [created, user, assistant] = events else {
        panic!("exact replay event sequence");
    };
    assert_eq!(created.event.event_type(), "conversation.created");
    assert_eq!(created.event.aggregate_id(), expectation.conversation_id);
    assert_eq!(created.event.sequence(), 1);
    assert_eq!(
        created.event.payload(),
        &CanonicalReplayPayload::Conversation(
            gocode_runtime_client::ConversationReplayPayload::Created {
                workspace_id: expectation.workspace_id,
            },
        )
    );
    for (replayed, message, sequence) in [
        (user, &expectation.timeline.messages[0], 2),
        (assistant, &expectation.timeline.messages[1], 3),
    ] {
        assert_eq!(replayed.event.event_type(), "conversation.message.appended");
        assert_eq!(replayed.event.aggregate_id(), expectation.conversation_id);
        assert_eq!(replayed.event.sequence(), sequence);
        assert_eq!(
            replayed.event.payload(),
            &CanonicalReplayPayload::Conversation(
                gocode_runtime_client::ConversationReplayPayload::MessageAppended {
                    role: message.role,
                    message_id: message.message_id,
                    task_run_id: message.task_run_id,
                    attempt_id: message.attempt_id,
                    text: message.text.clone(),
                },
            )
        );
    }
}

fn id(value: &str) -> CanonicalId {
    CanonicalId::parse(value).expect("fixed UUIDv7")
}

fn identity(command_id: CanonicalId, key: &str) -> CommandIdentity {
    CommandIdentity::new(command_id, key).expect("fixed idempotency identity")
}
