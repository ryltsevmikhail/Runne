use std::sync::Arc;

use gocode_api::CreateConversationInput;
use gocode_application::commands::BeginConversationTextInput;
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextService, ConversationTextServiceError,
};
use gocode_application::ports::{
    ApplicationCommandContext, PrincipalId, RuntimeAuthorityId, StorageFailureKind,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_domain::event::Actor;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use gocode_domain::message::MessageText;
use gocode_store::schema::open_with_pragmas;
use gocode_store::store::StoreTransaction;

const MARKER: &[u8] = b"task-seven-inert-marker";

#[derive(Clone, Copy)]
enum GuardMode {
    Marker,
    Unavailable,
}

struct BoundaryGuard {
    mode: GuardMode,
}

impl ProhibitedContentPort for BoundaryGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        match self.mode {
            GuardMode::Unavailable => Err(ContentGuardError::Unavailable),
            GuardMode::Marker if contains(bytes, MARKER) => {
                Ok(ContentDisposition::Prohibited { policy_epoch: 2 })
            }
            GuardMode::Marker => Ok(ContentDisposition::Allowed { policy_epoch: 2 }),
        }
    }
}

struct AvailableGuard;

impl ProhibitedContentPort for AvailableGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn context(command_id: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command_id.parse::<CommandId>().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("persistence-boundary-test").unwrap(),
    }
}

fn row_counts(path: &str, conversation_id: ConversationId) -> (i64, i64, i64, i64) {
    let connection = open_with_pragmas(path).unwrap();
    let events = connection
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    let receipts = connection
        .query_row("SELECT COUNT(*) FROM command_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    let conversation_head = connection
        .query_row(
            "SELECT current_version FROM aggregate_streams
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let next_global_position = connection
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    (events, receipts, conversation_head, next_global_position)
}

fn assert_denied_without_mutation(mode: GuardMode) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("persistence.sqlite");
    let path = path.to_str().unwrap();
    let authority = RuntimeAuthorityId("persistence-boundary".into());
    let store = StoreTransaction::open(
        path,
        authority.clone(),
        Arc::new(BoundaryGuard {
            mode: GuardMode::Marker,
        }),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000071".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000072".parse().unwrap();
    let create = context(
        "018f2e3a-7000-7000-8000-000000000073",
        "create-before-denial",
    );
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create.command_id,
                idempotency_key: create.idempotency_key.clone(),
            },
        )
        .unwrap();
    let before = row_counts(path, conversation_id);

    let generate = context("018f2e3a-7000-7000-8000-000000000074", "denied-generation");
    let service = ConversationTextService::new(
        store,
        StoreTransaction::open(path, authority.clone(), Arc::new(BoundaryGuard { mode })).unwrap(),
        authority,
        Arc::new(AvailableGuard),
    );
    let result = service.begin(
        &generate,
        BeginConversationTextInput {
            conversation_id,
            expected_version: 1,
            text: MessageText::new(std::str::from_utf8(MARKER).unwrap()).unwrap(),
        },
    );

    assert!(matches!(
        result,
        Err(ConversationTextServiceError::Commit(
            gocode_application::ports::CommitError::StorageFailure(
                StorageFailureKind::PolicyDenied
            )
        ))
    ));
    assert_eq!(row_counts(path, conversation_id), before);
}

#[test]
fn prohibited_final_event_bytes_roll_back_before_first_insert() {
    assert_denied_without_mutation(GuardMode::Marker);
}

#[test]
fn unavailable_final_event_guard_rolls_back_before_first_insert() {
    assert_denied_without_mutation(GuardMode::Unavailable);
}
