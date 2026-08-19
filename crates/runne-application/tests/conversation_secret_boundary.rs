use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_text_service::{
    ConversationTextService, ConversationTextServiceError,
};
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    ApplicationCommandContext, BeginTextGenerationCommit, CommitError, ConversationCommit,
    ConversationCommitResult, ConversationLoadedStream, ConversationReceiptLookup,
    ConversationRepository, ConversationTextRepository, EventStore, EventStoreError,
    FinishTextGenerationCommit, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream,
    PrincipalId, RejectTextGenerationCommit, RuntimeAuthorityId, TextGenerationCommitResult,
    TextGenerationReceiptLookup,
};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_domain::event::Actor;
use runne_domain::id::{
    AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, MessageId, TaskRunId,
};
use runne_domain::message::MessageText;

const MARKER: &[u8] = b"registered-test-material";

#[derive(Clone, Default)]
struct RecordingRepository {
    receipt_lookups: Arc<AtomicUsize>,
    loads: Arc<AtomicUsize>,
    commits: Arc<AtomicUsize>,
}

impl RecordingRepository {
    fn receipt_lookups(&self) -> usize {
        self.receipt_lookups.load(Ordering::SeqCst)
    }

    fn loads(&self) -> usize {
        self.loads.load(Ordering::SeqCst)
    }

    fn commits(&self) -> usize {
        self.commits.load(Ordering::SeqCst)
    }
}

impl ConversationRepository for RecordingRepository {
    fn load_conversation(
        &self,
        _conversation_id: ConversationId,
    ) -> Result<ConversationLoadedStream, EventStoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Err(EventStoreError::NotFound)
    }

    fn lookup_conversation_receipt(
        &self,
        _command_id: CommandId,
        _idempotency_key: &IdempotencyKey,
        _idempotency_scope: &IdempotencyScope,
        _fingerprint: &CommandFingerprint,
    ) -> Result<ConversationReceiptLookup, CommitError> {
        panic!("create-conversation lookup is outside this test")
    }

    fn commit_conversation(
        &self,
        _payload: ConversationCommit,
    ) -> Result<ConversationCommitResult, CommitError> {
        panic!("create-conversation commit is outside this test")
    }
}

impl ConversationTextRepository for RecordingRepository {
    fn lookup_text_generation_receipt(
        &self,
        _command_id: CommandId,
        _idempotency_key: &IdempotencyKey,
        _idempotency_scope: &IdempotencyScope,
        _fingerprint: &CommandFingerprint,
    ) -> Result<TextGenerationReceiptLookup, CommitError> {
        self.receipt_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(TextGenerationReceiptLookup::Miss)
    }

    fn begin_text_generation(
        &self,
        _payload: BeginTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        unreachable!("guarded input must not reach persistence")
    }

    fn finish_text_generation(
        &self,
        _payload: FinishTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        unreachable!("guarded input must not reach persistence")
    }

    fn reject_text_generation(
        &self,
        _payload: RejectTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        unreachable!("guarded input must not reach persistence")
    }
}

impl EventStore for RecordingRepository {
    fn load_task_run(&self, _taskrun_id: TaskRunId) -> Result<LoadedStream, EventStoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Err(EventStoreError::NotFound)
    }
}

#[derive(Clone, Default)]
struct RecordingIds {
    calls: Arc<AtomicUsize>,
}

impl RecordingIds {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn called<T>(&self) -> Result<T, IdGenerationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(IdGenerationError::Unavailable)
    }
}

impl IdGenerator for RecordingIds {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        self.called()
    }

    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
        self.called()
    }

    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        self.called()
    }

    fn next_message_id(&self) -> Result<MessageId, IdGenerationError> {
        self.called()
    }

    fn next_event_ids(&self, _count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        self.called()
    }
}

struct RegisteredMarkerGuard;

impl ProhibitedContentPort for RegisteredMarkerGuard {
    fn inspect(
        &self,
        boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        assert_eq!(boundary, CanonicalContentBoundary::CanonicalMutation);
        Ok(
            if bytes.windows(MARKER.len()).any(|window| window == MARKER) {
                ContentDisposition::Prohibited { policy_epoch: 1 }
            } else {
                ContentDisposition::Allowed { policy_epoch: 1 }
            },
        )
    }
}

fn command_context() -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: "018f2e3a-7000-7000-8000-000000000001".parse().unwrap(),
        idempotency_key: IdempotencyKey::new("guard-ordering").unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("application-test").unwrap(),
    }
}

#[test]
fn prohibited_user_input_is_rejected_before_fingerprint_visible_side_effects() {
    let repository = RecordingRepository::default();
    let ids = RecordingIds::default();
    let service = ConversationTextService::new(
        repository.clone(),
        ids.clone(),
        RuntimeAuthorityId("application-test".into()),
        Arc::new(RegisteredMarkerGuard),
    );
    let text = MessageText::new(format!(
        "ordinary prefix {} ordinary suffix",
        String::from_utf8_lossy(MARKER)
    ))
    .unwrap();

    let error = service
        .begin(
            &command_context(),
            BeginConversationTextInput {
                conversation_id: "018f2e3a-7000-7000-8000-000000000002".parse().unwrap(),
                expected_version: 1,
                text,
            },
        )
        .unwrap_err();

    assert_eq!(
        error,
        ConversationTextServiceError::ProhibitedSecretMaterial
    );
    assert!(!format!("{error:?}").contains(&String::from_utf8_lossy(MARKER).to_string()));
    assert_eq!(ids.calls(), 0);
    assert_eq!(repository.receipt_lookups(), 0);
    assert_eq!(repository.loads(), 0);
    assert_eq!(repository.commits(), 0);
}
