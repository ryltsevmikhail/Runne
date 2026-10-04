struct SuccessorRow {
    predecessor: Vec<u8>,
    successor: Vec<u8>,
    attempt: Vec<u8>,
    prior_id: Option<Vec<u8>>,
    prior_version: Option<i64>,
    marker_id: Option<Vec<u8>>,
    conversation: Vec<u8>,
    workspace: Vec<u8>,
    ack: Vec<u8>,
    input_digest: Vec<u8>,
    command_fingerprint: Vec<u8>,
    key_digest: Vec<u8>,
    provider: Option<String>,
    profile: Option<String>,
    profile_digest: Option<Vec<u8>>,
    model: Option<String>,
    revision: Option<String>,
    model_digest: Option<Vec<u8>>,
    submit_id: Vec<u8>,
    submit_version: i64,
    release_reason: String,
    release_id: Vec<u8>,
    release_version: i64,
    idempotency_key: Vec<u8>,
    receipt_fingerprint: Vec<u8>,
    scope_bytes: Vec<u8>,
    principal_id: String,
    principal_digest: Vec<u8>,
    predecessor_input_digest: Vec<u8>,
    origin_kind: String,
    project_id: Option<Vec<u8>>,
    origin_operation: i64,
    current_version: i64,
    tail_id: Option<Vec<u8>>,
    command_outcome: Vec<u8>,
    marker_version: Option<i64>,
}

fn v57_row_events_match(connection: &Connection, row: &SuccessorRow) -> SqliteResult<bool> {
    v57_row_events_match_inner(connection, row, true)
}

fn v57_row_events_match_for_v62_audit(
    connection: &Connection,
    row: &SuccessorRow,
) -> SqliteResult<bool> {
    v57_row_events_match_inner(connection, row, false)
}

include!("v57_taskrun_unknown_successor_event_validation.rs");
include!("v57_taskrun_unknown_successor_command_outcome.rs");

include!("v57_taskrun_unknown_successor_release.rs");

include!("v57_taskrun_unknown_successor_event_match.rs");
