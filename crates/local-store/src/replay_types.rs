struct VerifiedReplayState {
    checkpoint: ReplayCheckpoint,
    projection: StoredConversationProjection,
}

type StoredJournalTransition = (
    String,
    String,
    i64,
    i64,
    Vec<u8>,
    String,
    i64,
    String,
    Vec<u8>,
);

type StoredReplayRow = (
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    i64,
);

struct VerifiedJournalTail {
    cursor: String,
    generation: u64,
    event_sequence: u64,
    projection_revision: u64,
    projection_digest: String,
    projected_payload: Vec<u8>,
}
