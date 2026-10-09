use super::super::diagnostic::{diagnostic, fixture_count};
use super::*;
#[path = "verify_invocations.rs"]
mod invocations;
pub(super) use invocations::invocation_count;

pub(super) async fn wait_results(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    count: usize,
    runtime_root: &std::path::Path,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while result_count(database, task) < count {
        if tokio::time::Instant::now() >= deadline {
            let task_run = client
                .get_task_run(task)
                .await
                .expect("read public TaskRun after D2 result timeout");
            let state_and_terminal = (task_run.state(), task_run.terminal_result());
            panic!(
                "D2 result count did not reach {count}; state/terminal={state_and_terminal:?}: {}",
                diagnostic(database, task, runtime_root)
            );
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert_eq!(result_count(database, task), count);
}

pub(super) async fn wait_success(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> runne_runtime_client::TaskRunSnapshot {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(50);
    loop {
        let snapshot = client.get_task_run(task).await.expect("read D2 TaskRun");
        if matches!(
            snapshot.state(),
            runne_runtime_client::TaskRunState::Succeeded
                | runne_runtime_client::TaskRunState::Failed
                | runne_runtime_client::TaskRunState::PolicyDenied
                | runne_runtime_client::TaskRunState::Unrecoverable
        ) {
            return snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "D2 TaskRun did not finish: {}",
            diagnostic(database, task, runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(super) fn assert_request_counts(runtime_root: &std::path::Path) {
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        3
    );
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-connection-count"),
        3
    );
}

fn task_bytes(task: runne_runtime_client::CanonicalId) -> [u8; 16] {
    uuid::Uuid::parse_str(&task.to_string())
        .expect("task id")
        .into_bytes()
}

pub(super) fn result_count(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> usize {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only result view");
    connection
        .query_row(
            "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND state='result' AND result_truncated=0",
            [task_bytes(task).as_slice()],
            |row| row.get::<_, usize>(0),
        )
        .expect("read result state count")
}

pub(super) fn reserved_effect_count(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> u32 {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only budget view");
    connection
        .query_row(
            "SELECT effects_used FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            [task_bytes(task).as_slice()],
            |row| row.get(0),
        )
        .expect("read effects used")
}

pub(super) fn release_intent_count(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> u32 {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only release view");
    connection
        .query_row(
            "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND release_started=1",
            [task_bytes(task).as_slice()],
            |row| row.get(0),
        )
        .expect("read durable native release count")
}

pub(super) fn assert_encrypted_results(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    expected_count: usize,
) {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only durable result view");
    let mut statement = connection
        .prepare("SELECT state,length(canonical_arguments),args_plaintext_len,length(helper_receipt_bytes),receipt_plaintext_len,result_bytes IS NULL,result_truncated,release_started,local_stop_state,managed_area_identity=empty_proof_identity AND empty_proof_identity IS NOT NULL FROM taskrun_tool_invocations WHERE taskrun_id=?1 ORDER BY round_index")
        .expect("prepare durable encrypted result query");
    let rows = statement
        .query_map([task_bytes(task).as_slice()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, usize>(1)?,
                row.get::<_, usize>(2)?,
                row.get::<_, usize>(3)?,
                row.get::<_, usize>(4)?,
                row.get::<_, bool>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, bool>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, bool>(9)?,
            ))
        })
        .expect("query durable result rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("decode result metadata");
    assert_eq!(rows.len(), expected_count);
    for row in &rows {
        assert_eq!(row.0, "result");
        assert_eq!(row.1, row.2 + 16, "arguments remain AEAD ciphertext");
        assert_eq!(row.3, row.4 + 16, "helper receipt remains AEAD ciphertext");
        assert!(row.5 && !row.6 && row.7);
        assert_eq!(row.8, 2, "native managed area has empty proof");
        assert!(row.9, "empty proof is bound to the exact managed area");
    }
    assert_eq!(
        result_count(database, task),
        expected_count,
        "result readback is stable"
    );
    assert_eq!(
        reserved_effect_count(database, task),
        expected_count as u32,
        "approval replay did not repeat effects"
    );
}

pub(super) async fn assert_conversation_receipt(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    let scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::Conversation,
        conversation_id,
    );
    let mut found_historical = false;
    let mut live = client
        .catch_up(scope, None, |delivery| {
            found_historical |= matches!(
                delivery.event().payload(),
                runne_runtime_client::CanonicalReplayPayload::Conversation(
                    runne_runtime_client::ConversationReplayPayload::MessageAppended {
                        role: runne_runtime_client::ConversationMessageRole::Assistant,
                        task_run_id: owner,
                        text,
                        ..
                    }
                ) if *owner == task && text == super::FINAL_TEXT
            );
            Ok::<_, ()>(())
        })
        .await
        .expect("conversation receipt replay catch-up");
    if found_historical {
        return;
    }
    for _ in 0..32 {
        let event = tokio::time::timeout(Duration::from_secs(5), live.next_event())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "conversation replay timeout: {}; {}",
                    diagnostic(database, task, runtime_root),
                    conversation_diagnostic(database, conversation_id, task)
                )
            })
            .expect("conversation replay event");
        if let runne_runtime_client::ReplayStreamEvent::Delivery(delivery) = event {
            let found = matches!(
                delivery.event().payload(),
                runne_runtime_client::CanonicalReplayPayload::Conversation(
                    runne_runtime_client::ConversationReplayPayload::MessageAppended {
                        role: runne_runtime_client::ConversationMessageRole::Assistant,
                        task_run_id: owner,
                        text,
                        ..
                    }
                ) if *owner == task && text == super::FINAL_TEXT
            );
            live.acknowledge(&delivery)
                .await
                .expect("acknowledge conversation receipt");
            if found {
                return;
            }
        }
    }
    panic!(
        "final D2 assistant Conversation receipt was not replayed: {}; {}",
        diagnostic(database, task, runtime_root),
        conversation_diagnostic(database, conversation_id, task)
    );
}

fn conversation_diagnostic(
    database: &std::path::Path,
    conversation_id: runne_runtime_client::CanonicalId,
    task: runne_runtime_client::CanonicalId,
) -> String {
    use runne_store::codec::{ConversationEventCodec, StoreCodec};
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only Conversation diagnostic");
    let aggregate_id = uuid::Uuid::parse_str(&conversation_id.to_string())
        .expect("Conversation UUID")
        .into_bytes();
    let head: Option<i64> = connection
        .query_row(
            "SELECT current_version FROM aggregate_streams WHERE aggregate_type=2 AND aggregate_id=?1",
            [aggregate_id.as_slice()],
            |row| row.get(0),
        )
        .ok();
    let mut statement = connection
        .prepare("SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1 ORDER BY sequence")
        .expect("prepare read-only Conversation event query");
    let payloads = statement
        .query_map([aggregate_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .expect("query Conversation events")
        .collect::<Result<Vec<_>, _>>()
        .expect("read Conversation event payloads");
    let assistant_events = payloads
        .iter()
        .filter(|payload| {
            matches!(
                ConversationEventCodec.decode(payload),
                Ok(runne_domain::conversation::ConversationEvent::AssistantMessageAppended { .. })
            )
        })
        .count();
    format!(
        "conversation_id={conversation_id} task={task} head={head:?} events={} assistant_events={assistant_events}",
        payloads.len()
    )
}
