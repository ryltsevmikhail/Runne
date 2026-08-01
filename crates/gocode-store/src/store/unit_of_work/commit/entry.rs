impl StoreTransaction {
    pub(super) fn commit_impl(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
        if payload.events.len() > MAX_EVENTS_PER_COMMIT {
            return Err(CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            ));
        }
        if payload.events.is_empty() {
            return Err(CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            ));
        }

        let mut conn = self.inner.writer.lock().unwrap();
        let taskrun_id = match payload.events[0].correlation_id() {
            AggregateId::TaskRun(taskrun_id) => *taskrun_id,
            _ => {
                return Err(CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                ));
            }
        };
        for event in &payload.events {
            match event.correlation_id() {
                AggregateId::TaskRun(correlation_id) if *correlation_id == taskrun_id => {}
                _ => {
                    return Err(CommitError::StorageFailure(
                        gocode_application::ports::StorageFailureKind::IntegrityViolation,
                    ));
                }
            }
        }
        let taskrun_bytes = taskrun_id.as_bytes();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::Unavailable,
                )
            })?;
        self.commit_transaction(tx, payload, taskrun_id, taskrun_bytes)
    }

}
