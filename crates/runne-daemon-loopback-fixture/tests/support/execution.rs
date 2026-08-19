use std::path::Path;

use runne_daemon_loopback_fixture::request_count;

use super::ConversationExpectation;

#[derive(Debug)]
pub struct ExecutionStage {
    pub accepted_request_count: u64,
    pub journal_row_count: u64,
    pub journal_sequences: Vec<u64>,
    pub terminal_outbox_total: u64,
    pub terminal_outbox_pending: u64,
}

pub fn pending_outbox(root: &Path) -> u64 {
    let connection = rusqlite::Connection::open(root.join("runne-daemon/event-log.db"))
        .expect("open fixture event log");
    connection
        .query_row(
            "SELECT COUNT(*) FROM provider_terminal_outbox WHERE state = 1",
            [],
            |row| row.get(0),
        )
        .expect("count pending terminal outbox")
}

pub fn accepted_requests(root: &Path) -> u64 {
    request_count(root).expect("read non-secret provider request count")
}

pub fn execution_stage(root: &Path) -> ExecutionStage {
    let connection = rusqlite::Connection::open(root.join("runne-daemon/event-log.db"))
        .expect("open fixture event log");
    let journal_row_count = connection
        .query_row("SELECT COUNT(*) FROM provider_stream_journal", [], |row| {
            row.get(0)
        })
        .expect("count journal rows");
    let journal_sequences = connection
        .prepare("SELECT sequence FROM provider_stream_journal ORDER BY sequence")
        .expect("prepare journal sequence query")
        .query_map([], |row| row.get(0))
        .expect("read journal sequences")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect journal sequences");
    let terminal_outbox_total = connection
        .query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |row| {
            row.get(0)
        })
        .expect("count terminal outbox");
    ExecutionStage {
        accepted_request_count: accepted_requests(root),
        journal_row_count,
        journal_sequences,
        terminal_outbox_total,
        terminal_outbox_pending: pending_outbox(root),
    }
}

pub fn assert_first_activation_stages(
    execution: &ExecutionStage,
    conversation: &ConversationExpectation,
) {
    assert_eq!(
        execution.accepted_request_count, 1,
        "stage=accepted_request_count values={execution:?}"
    );
    assert_eq!(
        execution.journal_row_count, 4,
        "stage=journal_row_count values={execution:?}"
    );
    assert_eq!(
        execution.journal_sequences,
        [0, 1, 2, 3],
        "stage=journal_sequences values={execution:?}"
    );
    assert_eq!(
        execution.terminal_outbox_total, 1,
        "stage=terminal_outbox_total values={execution:?}"
    );
    assert_eq!(
        execution.terminal_outbox_pending, 1,
        "stage=terminal_outbox_pending values={execution:?}"
    );
    conversation.assert_process_one();
}
