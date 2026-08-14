struct AllowDelivery;

impl ReplayDeliveryPrecommitGuard for AllowDelivery {
    fn inspect(&self, _: &ReplaySession, _: &[ReplayEvent]) -> Result<(), ReplayError> {
        Ok(())
    }
}

impl TransactionalAdmissionStore {
    fn stored_epoch(&self, session_id: &[u8; 16]) -> i64 {
        self.connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT authorization_epoch FROM _replay_subscriptions WHERE session_id = ?1",
                [session_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    }
}
