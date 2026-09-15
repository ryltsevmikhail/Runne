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

/// Best-effort stage classification from durable fixture facts. This is only
/// used when the client receives an unexpected response and never affects the
/// success assertions.
#[allow(dead_code)]
pub fn diagnostic_stage(root: &Path) -> String {
    let Ok(connection) = rusqlite::Connection::open(root.join("runne-daemon/event-log.db")) else {
        return "server_stage=unobservable".to_owned();
    };
    let Some(accepted_request_count) = request_count(root).ok() else {
        return "server_stage=unobservable".to_owned();
    };
    let Ok(journal_row_count) =
        connection.query_row("SELECT COUNT(*) FROM provider_stream_journal", [], |row| {
            row.get::<_, u64>(0)
        })
    else {
        return "server_stage=unobservable".to_owned();
    };
    let Ok(terminal_outbox_total) =
        connection.query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |row| {
            row.get::<_, u64>(0)
        })
    else {
        return "server_stage=unobservable".to_owned();
    };
    let Ok(terminal_outbox_pending) = connection.query_row(
        "SELECT COUNT(*) FROM provider_terminal_outbox WHERE state = 1",
        [],
        |row| row.get::<_, u64>(0),
    ) else {
        return "server_stage=unobservable".to_owned();
    };
    let execution = ExecutionStage {
        accepted_request_count,
        journal_row_count,
        journal_sequences: Vec::new(),
        terminal_outbox_total,
        terminal_outbox_pending,
    };
    let stage = diagnostic_stage_name(
        execution.accepted_request_count,
        execution.journal_row_count,
        execution.terminal_outbox_total,
        execution.terminal_outbox_pending,
    );
    format!(
        "server_stage={stage} accepted={} journal_rows={} outbox_total={} outbox_pending={}",
        execution.accepted_request_count,
        execution.journal_row_count,
        execution.terminal_outbox_total,
        execution.terminal_outbox_pending
    )
}

fn diagnostic_stage_name(
    accepted_request_count: u64,
    journal_row_count: u64,
    terminal_outbox_total: u64,
    terminal_outbox_pending: u64,
) -> &'static str {
    if accepted_request_count == 0 {
        "provider_accept_not_observed"
    } else if journal_row_count == 0 {
        "provider_stream_journal_not_observed"
    } else if terminal_outbox_total == 0 {
        "terminal_outbox_not_observed"
    } else if terminal_outbox_pending != 0 {
        "terminal_outbox_pending"
    } else {
        "terminal_outbox_not_pending"
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

#[cfg(test)]
mod tests {
    use super::diagnostic_stage_name;

    #[test]
    fn diagnostic_stage_name_covers_durable_boundaries() {
        assert_eq!(
            diagnostic_stage_name(0, 0, 0, 0),
            "provider_accept_not_observed"
        );
        assert_eq!(
            diagnostic_stage_name(1, 0, 0, 0),
            "provider_stream_journal_not_observed"
        );
        assert_eq!(
            diagnostic_stage_name(1, 1, 0, 0),
            "terminal_outbox_not_observed"
        );
        assert_eq!(diagnostic_stage_name(1, 1, 1, 1), "terminal_outbox_pending");
        assert_eq!(
            diagnostic_stage_name(1, 1, 1, 0),
            "terminal_outbox_not_pending"
        );
    }
}
