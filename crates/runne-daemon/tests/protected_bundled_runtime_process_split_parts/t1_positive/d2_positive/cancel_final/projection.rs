use runne_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, RemoteCancellationEvidence, RemoteEffectOutcome,
    RemotePublicationDisposition, TaskRunState,
};
use runne_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
#[path = "projection/forged_claim.rs"]
mod forged_claim;
pub(super) use forged_claim::assert_forged_claim_history_is_rejected;

pub(super) async fn assert_cancelled_projection(
    client: &AuthenticatedRuntimeClient,
    database: &std::path::Path,
    task: CanonicalId,
    conversation: CanonicalId,
    version: u64,
    runtime_root: &std::path::Path,
) {
    let snapshot = client
        .get_task_run(task)
        .await
        .expect("public cancelled snapshot");
    assert_eq!(snapshot.state(), TaskRunState::Cancelled);
    assert_eq!(snapshot.stream_version(), version);
    super::super::super::diagnostic::clear_store_remote_stage();
    let effects = client
        .get_task_run_effects(task)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "public cancelled effect projection: {error:?}; {}",
                super::super::super::diagnostic::diagnostic(database, task, runtime_root)
            )
        });
    assert_eq!(effects.stream_version(), version);
    assert_ne!(
        effects.remote().cancellation(),
        RemoteCancellationEvidence::Confirmed
    );
    assert_eq!(
        effects.remote().publication(),
        RemotePublicationDisposition::Unknown,
        "the late terminal has no authenticated remote artifact, so publication remains unknown"
    );
    assert_eq!(effects.remote().outcome(), RemoteEffectOutcome::Unknown);
    assert_eq!(effects.local_command(), None);

    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only cancellation receipt view");
    let task_id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let task_payloads = payloads(&db, 1, &task_id);
    let cancelled = task_payloads
        .iter()
        .filter(|payload| {
            matches!(
                TaskRunEventCodec.decode(payload),
                Ok(runne_domain::task_run::TaskRunEvent::CancellationCompleted)
            )
        })
        .count();
    assert_eq!(cancelled, 1, "one exact TaskRun cancellation terminal");
    assert!(!task_payloads.iter().any(|payload| matches!(
        TaskRunEventCodec.decode(payload),
        Ok(
            runne_domain::task_run::TaskRunEvent::TaskRunCompleted { .. }
                | runne_domain::task_run::TaskRunEvent::LoopCycleCompleted { .. }
        )
    )));

    let conversation_id = uuid::Uuid::parse_str(&conversation.to_string())
        .expect("Conversation UUID")
        .into_bytes();
    let (artifacts, settlements): (i64, i64) = db
        .query_row(
            "SELECT count(*), (SELECT count(*) FROM provider_remote_terminal_settlements WHERE taskrun_id=?1)
             FROM provider_remote_terminal_artifacts WHERE taskrun_id=?1",
            [task_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read authenticated remote terminal fact counts");
    assert_eq!(
        artifacts, 0,
        "late journal frame did not become an authenticated terminal artifact"
    );
    assert_eq!(
        settlements, 0,
        "no remote settlement may be fabricated for that frame"
    );
    let conversation_payloads = payloads(&db, 2, &conversation_id);
    let matches = cancelled_terminals(&db, &conversation_id, &task_id);
    assert_eq!(
        matches.len(),
        1,
        "exactly one cancelled Conversation receipt"
    );
    let (terminal, command_id, sequence) = matches.into_iter().next().expect("one cancellation");
    let attempt = match terminal {
        runne_domain::conversation::ConversationEvent::GenerationFailed { attempt_id, .. } => {
            attempt_id
        }
        _ => unreachable!(),
    };
    let outcome: Vec<u8> = db
        .query_row(
            "SELECT command_outcome FROM command_receipts WHERE command_id=?1",
            [command_id.as_slice()],
            |row| row.get(0),
        )
        .expect("read original Generate command receipt");
    let receipt = runne_store::codec::TextGenerationReceiptCodec
        .decode(&outcome)
        .expect("decode original Generate command receipt");
    assert_eq!(
        receipt.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert_eq!(receipt.taskrun_id.as_bytes(), &task_id);
    assert_eq!(receipt.attempt_id, attempt);
    assert_eq!(receipt.conversation_id.as_bytes(), &conversation_id);
    assert_eq!(
        i64::try_from(receipt.conversation_version).ok(),
        Some(sequence)
    );
    let task_head: i64 = db.query_row(
        "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
        [task_id.as_slice()],
        |row| row.get(0),
    ).expect("read terminal TaskRun head");
    assert_eq!(i64::try_from(receipt.taskrun_version).ok(), Some(task_head));
    assert!(!conversation_payloads.iter().any(|payload| matches!(
        ConversationEventCodec.decode(payload),
        Ok(runne_domain::conversation::ConversationEvent::AssistantMessageAppended { taskrun_id, .. })
            if taskrun_id.as_bytes() == &task_id
    )));
}

fn payloads(db: &rusqlite::Connection, aggregate: i64, id: &[u8; 16]) -> Vec<Vec<u8>> {
    db.prepare("SELECT payload FROM events WHERE aggregate_type=?1 AND aggregate_id=?2")
        .expect("prepare cancellation event query")
        .query_map(rusqlite::params![aggregate, id.as_slice()], |row| {
            row.get(0)
        })
        .expect("query cancellation events")
        .collect::<Result<Vec<_>, _>>()
        .expect("read cancellation events")
}

fn cancelled_terminals(
    db: &rusqlite::Connection,
    conversation_id: &[u8; 16],
    task_id: &[u8; 16],
) -> Vec<(runne_domain::conversation::ConversationEvent, Vec<u8>, i64)> {
    let mut statement = db
        .prepare("SELECT payload,command_id,sequence FROM events WHERE aggregate_type=2 AND aggregate_id=?1 ORDER BY sequence")
        .expect("prepare Conversation cancellation query");
    let events = statement
        .query_map([conversation_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .expect("query Conversation cancellation events")
        .collect::<Result<Vec<_>, _>>()
        .expect("read Conversation cancellation events");
    events
        .into_iter()
        .filter_map(
            |(payload, command, sequence)| match ConversationEventCodec.decode(&payload) {
                Ok(
                    event @ runne_domain::conversation::ConversationEvent::GenerationFailed {
                        taskrun_id,
                        reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
                        ..
                    },
                ) if taskrun_id.as_bytes() == task_id => Some((event, command, sequence)),
                _ => None,
            },
        )
        .collect()
}
