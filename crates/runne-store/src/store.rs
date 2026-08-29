//! Store — SQLite-backed persistence adapter.
//!
//! Provides:
//! - [`StoreTransaction`] — opens, configures, and migrates the database
//! - [`EventStore`] impl — loads task run event streams
//! - [`UnitOfWork`] impl — idempotency lookup + atomic commit
//! - [`IdGenerator`] impl — UUIDv7-based unique IDs
//! - [`Clock`] impl — system wall clock in microseconds

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, BeginTextGenerationCommit, Clock, ClockError, CommandCommit, CommitError,
    CommitResult, ConversationCommit, ConversationCommitResult, ConversationLoadedStream,
    ConversationReceipt, ConversationReceiptLookup, ConversationRepository,
    ConversationTextRepository, EventStore as AppEventStore, EventStoreError,
    FinishTextGenerationCommit, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream,
    OperationTag, ReceiptLookup, RejectTextGenerationCommit, ReplayEvent, RuntimeAuthorityId,
    StorageFailureKind, TextGenerationCommitResult, TextGenerationPhase, TextGenerationReceipt,
    TextGenerationReceiptLookup, UnitOfWork,
};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use runne_application::replay_service::{
    measured_conversation_replay_event_bytes, measured_taskrun_replay_event_bytes,
    validate_replay_writer_event_size,
};
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::{Actor, EventEnvelope, Sensitivity, UncommittedEvent};
use runne_domain::id::{
    AggregateId, AttemptId, CommandId, ConversationId, EventId, IntegrityDigest, MessageId,
    TaskRunId,
};
use runne_domain::task_run::TaskRunEvent;
use runne_domain::timestamp::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

use crate::codec::{
    CommandOutcomeCodec, ConversationEventCodec, ConversationReceiptCodec, IdempotencyScopeCodec,
    StoreCodec, TaskRunEventCodec, TextGenerationReceiptCodec,
};
use crate::integrity::{
    compute_integrity_digest_v2_with_global_position, compute_integrity_digest_with_global_position,
};
use crate::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, open_managed_connection,
    publication_from_managed, readiness_from_managed,
};

/// Maximum event count per commit (safety bound).
const MAX_EVENTS_PER_COMMIT: usize = 1_000;

const CORRELATION_TYPE_TASK_RUN: i64 = 1;
const CORRELATION_TYPE_CONVERSATION: i64 = 2;
const INTEGRITY_PROFILE_V1: i64 = 1;
const INTEGRITY_PROFILE_V2: i64 = 2;

fn stored_sensitivity(value: i64) -> Result<Sensitivity, EventStoreError> {
    match value {
        0 => Ok(Sensitivity::Public),
        1 => Ok(Sensitivity::Internal),
        2 => Ok(Sensitivity::Sensitive),
        _ => Err(EventStoreError::CorruptData),
    }
}

const fn sensitivity_value(value: Sensitivity) -> i64 {
    match value {
        Sensitivity::Public => 0,
        Sensitivity::Internal => 1,
        Sensitivity::Sensitive => 2,
    }
}

/// Inner state shared between clones via `Arc`.
struct StoreInner {
    writer: Mutex<ManagedConnection>,
    reader: Mutex<ManagedConnection>,
    id_counter: AtomicU64,
}

/// SQLite-backed store with a single writer connection.
///
/// Implements [`AppEventStore`], [`UnitOfWork`], [`IdGenerator`], and [`Clock`].
/// Safe to clone — clones share the same connections via `Arc`.
///
/// # Concurrency
///
/// All writes go through a single `Mutex<Connection>`. Reads (loads, receipt
/// lookups) use a separate read connection to avoid blocking the writer.
#[derive(Clone)]
pub struct StoreTransaction {
    inner: Arc<StoreInner>,
    runtime_authority_id: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

/// Current time as Unix microseconds (for stream row creation).
fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

mod append_helpers;
mod clock;
mod component_guard;
mod conversation;
mod core;
mod correlation;
mod enrollment_launch;
mod event_context;
mod event_guard;
mod events;
mod ids;
mod parse_helpers;
mod position_helpers;
pub mod process;
mod provider_terminal;
pub(crate) mod snapshot;
mod text;
mod text_receipt_helpers;
mod text_validation_helpers;
mod unit_of_work;

use correlation::StoredCorrelationType;
pub use enrollment_launch::EnrollmentLaunchGenerationError;

#[cfg(test)]
mod enrollment_launch_tests;
#[cfg(test)]
mod tests {
    use super::event_guard::*;
    use super::*;
    use runne_domain::id::{IdempotencyKey, MessageId};
    use runne_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};
    use runne_security::SecretBroker;

    fn available_guard() -> Arc<dyn ProhibitedContentPort> {
        Arc::new(SecretBroker::new().prohibited_content_guard())
    }

    fn temp_db_path(name: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos();
        let runtime_root = std::env::temp_dir().join(format!("runne-store-{name}-{unique}"));
        let daemon = runtime_root.join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        daemon
            .join("event-log.sqlite")
            .to_string_lossy()
            .into_owned()
    }

    fn cleanup_db(db_path: &str) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{db_path}{suffix}"));
        }
        if let Some(daemon) = Path::new(db_path).parent() {
            let _ = std::fs::remove_dir(daemon);
            if let Some(runtime_root) = daemon.parent() {
                let _ = std::fs::remove_dir(runtime_root);
            }
        }
    }

    #[test]
    fn public_store_open_rejects_memory_database() {
        let result = StoreTransaction::open(
            ":memory:",
            RuntimeAuthorityId("test-host".into()),
            available_guard(),
        );

        assert!(matches!(
            result,
            Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
        ));
    }

    #[test]
    fn append_guard_rejects_json_escape_expanded_canonical_event() {
        let conversation_id = ConversationId::from_bytes([0x11; 16]);
        let event = UncommittedEvent::from_parts(
            EventId::from_bytes([0x22; 16]),
            AggregateId::Conversation(conversation_id),
            AggregateId::Conversation(conversation_id),
            None,
            CommandId::from_bytes([0x33; 16]),
            IdempotencyKey::new("oversized-replay-event").unwrap(),
            1,
            Actor::new("test-actor").unwrap(),
            Sensitivity::Sensitive,
            ConversationEvent::UserMessageAppended {
                message_id: MessageId::from_bytes([0x44; 16]),
                taskrun_id: TaskRunId::from_bytes([0x55; 16]),
                attempt_id: AttemptId::from_bytes([0x66; 16]),
                text: MessageText::new("\0".repeat(MAX_MESSAGE_TEXT_BYTES)).unwrap(),
            },
        );
        let guard = available_guard();

        let error = guard_conversation_event(guard.as_ref(), &event, 1, 1, 0).unwrap_err();

        assert_eq!(
            error,
            CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)
        );
    }

    #[test]
    fn failed_stream_query_is_not_reported_as_missing() {
        let db_path = temp_db_path("reader-query-failure");
        let store = StoreTransaction::open(
            &db_path,
            RuntimeAuthorityId("test-host".into()),
            available_guard(),
        )
        .unwrap();
        store
            .inner
            .writer
            .lock()
            .unwrap()
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 DROP TABLE events;
                 DROP TABLE aggregate_streams;",
            )
            .unwrap();

        let result = store.load_task_run(TaskRunId::from_bytes([1; 16]));

        assert_eq!(result.unwrap_err(), EventStoreError::CorruptData);
        drop(store);
        cleanup_db(&db_path);
    }

    #[test]
    fn failed_receipt_query_is_not_reported_as_a_miss() {
        let db_path = temp_db_path("receipt-query-failure");
        let store = StoreTransaction::open(
            &db_path,
            RuntimeAuthorityId("test-host".into()),
            available_guard(),
        )
        .unwrap();
        store
            .inner
            .writer
            .lock()
            .unwrap()
            .execute_batch("DROP TABLE command_receipts;")
            .unwrap();
        let taskrun_id = TaskRunId::from_bytes([1; 16]);
        let scope = IdempotencyScope {
            runtime_authority_id: RuntimeAuthorityId("test-host".into()),
            principal_id: runne_application::ports::PrincipalId("test-principal".into()),
            operation: OperationTag::StartAttempt,
            aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id },
        };

        let result = store.lookup_receipt(
            CommandId::from_bytes([2; 16]),
            &IdempotencyKey::new("test-key").unwrap(),
            &scope,
            &CommandFingerprint::from_bytes([3; 32]),
        );

        assert_eq!(
            result.unwrap_err(),
            CommitError::StorageFailure(StorageFailureKind::CorruptData)
        );
        drop(store);
        cleanup_db(&db_path);
    }
}
