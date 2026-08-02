impl ReplayStore {
    /// Create a new `ReplayStore` from an existing SQLite connection.
    ///
    /// The connection must contain the `_replay_subscriptions` table.
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Generate a random session ID (16 bytes).
    fn generate_session_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        id
    }

    /// Deterministic authenticated reference used by gap responses.
    pub fn build_gap_range_ref(
        lineage_id: &EventLogLineageId,
        retention_generation: u64,
        missing_start: i64,
        missing_end: i64,
        scope: &ReplayScope,
        authorization_epoch: i64,
        server_secret: &[u8; 32],
    ) -> GapRangeRef {
        build_gap_range_ref(
            lineage_id,
            retention_generation,
            missing_start,
            missing_end,
            scope,
            authorization_epoch,
            server_secret,
        )
    }
}
