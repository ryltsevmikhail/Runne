// Settlement for an uncertain dispatch attempt that provably never delivered.
//
// The provider journal is a write-ahead log: the runtime commits its first
// delivery record before any bytes leave the process. An attempt that opened its
// effect window and then failed during local preparation therefore ends up
// `Uncertain` with an empty journal. Without a settlement such an attempt keeps
// blocking a safe runtime exit and every protected image upgrade, because the
// idle gate accepts only refused or settled attempts. This settlement proves
// that no delivery started and closes the window as a pre-effect rejection.

/// Durable evidence collected for one uncertain dispatch attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoDeliveryEvidence {
    /// Attempt state is `Uncertain`.
    pub uncertain: bool,
    /// No stream binding was ever committed.
    pub stream_unbound: bool,
    /// No settlement digest was ever committed.
    pub unsettled: bool,
    /// The delivery window opened and has already expired.
    pub window_expired: bool,
    /// Committed write-ahead journal records for the attempt.
    pub journal_records: u64,
    /// Opened stream poll flights.
    pub poll_flights: u64,
    /// Remote terminal artifacts.
    pub terminal_artifacts: u64,
    /// Remote response bindings.
    pub response_bindings: u64,
    /// Remote operation proofs.
    pub operation_proofs: u64,
    /// Authenticated unknown-terminal receipts.
    pub unknown_receipts: u64,
    /// Terminal outbox rows.
    pub terminal_outbox: u64,
    /// Remote terminal settlements.
    pub terminal_settlements: u64,
}

impl NoDeliveryEvidence {
    /// Whether the attempt provably stopped before any provider delivery began.
    #[must_use]
    pub const fn proves_no_delivery(self) -> bool {
        self.uncertain
            && self.stream_unbound
            && self.unsettled
            && self.window_expired
            && self.journal_records == 0
            && self.poll_flights == 0
            && self.terminal_artifacts == 0
            && self.response_bindings == 0
            && self.operation_proofs == 0
            && self.unknown_receipts == 0
            && self.terminal_outbox == 0
            && self.terminal_settlements == 0
    }
}

fn attempt_count(
    connection: &Connection,
    table: &str,
    attempt_id: DispatchAttemptId,
) -> Result<u64, ProviderStoreError> {
    connection
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE dispatch_attempt_id=?1"),
            params![attempt_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| u64::try_from(value).unwrap_or(u64::MAX))
        .map_err(|_| ProviderStoreError::Unavailable)
}

fn no_delivery_evidence(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
    now_unix_seconds: u64,
) -> Result<NoDeliveryEvidence, ProviderStoreError> {
    let (state, stream_bound, settled, expires_at) = connection
        .query_row(
            "SELECT attempt.state, attempt.stream_id IS NOT NULL,
                    attempt.settlement_digest IS NOT NULL, effect.effect_expires_at
             FROM provider_dispatch_attempts attempt
             JOIN provider_effect_starts effect
               ON effect.dispatch_attempt_id = attempt.attempt_id
             WHERE attempt.attempt_id = ?1",
            params![attempt_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderStoreError::Unavailable)?
        .ok_or(ProviderStoreError::NotFound)?;
    Ok(NoDeliveryEvidence {
        uncertain: state == 6,
        stream_unbound: !stream_bound,
        unsettled: !settled,
        window_expired: u64::try_from(expires_at).is_ok_and(|value| value <= now_unix_seconds),
        journal_records: attempt_count(connection, "provider_stream_journal", attempt_id)?,
        poll_flights: attempt_count(connection, "provider_poll_flights", attempt_id)?,
        terminal_artifacts: attempt_count(
            connection,
            "provider_remote_terminal_artifacts",
            attempt_id,
        )?,
        response_bindings: attempt_count(
            connection,
            "provider_remote_response_bindings",
            attempt_id,
        )?,
        operation_proofs: attempt_count(
            connection,
            "provider_remote_operation_proofs",
            attempt_id,
        )?,
        unknown_receipts: attempt_count(
            connection,
            "provider_unknown_terminal_receipts",
            attempt_id,
        )?,
        terminal_outbox: attempt_count(connection, "provider_terminal_outbox", attempt_id)?,
        terminal_settlements: attempt_count(
            connection,
            "provider_remote_terminal_settlements",
            attempt_id,
        )?,
    })
}

impl SqliteProviderDispatchStore {
    /// Lists uncertain attempts whose delivery window expired without one
    /// write-ahead journal record.
    ///
    /// # Errors
    ///
    /// Returns an unavailable failure when the store cannot be read.
    pub fn uncertain_without_delivery_candidates(
        &self,
        limit: usize,
        now_unix_seconds: u64,
    ) -> Result<Vec<DispatchAttemptId>, ProviderStoreError> {
        let limit = i64::try_from(limit).map_err(|_| ProviderStoreError::Unavailable)?;
        let now = i64::try_from(now_unix_seconds).map_err(|_| ProviderStoreError::Unavailable)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT attempt.attempt_id
                 FROM provider_dispatch_attempts attempt
                 JOIN provider_effect_starts effect
                   ON effect.dispatch_attempt_id = attempt.attempt_id
                 WHERE attempt.state = 6
                   AND attempt.stream_id IS NULL
                   AND attempt.settlement_digest IS NULL
                   AND effect.effect_expires_at <= ?1
                   AND NOT EXISTS(SELECT 1 FROM provider_stream_journal journal
                                  WHERE journal.dispatch_attempt_id = attempt.attempt_id)
                 ORDER BY effect.effect_started_at ASC, attempt.attempt_id ASC
                 LIMIT ?2",
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let rows = statement
            .query_map(params![now, limit], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let mut attempts = Vec::new();
        for row in rows {
            let bytes = row.map_err(|_| ProviderStoreError::Unavailable)?;
            let bytes: [u8; 16] = bytes
                .try_into()
                .map_err(|_| ProviderStoreError::Unavailable)?;
            attempts.push(DispatchAttemptId::from_bytes(bytes));
        }
        Ok(attempts)
    }

    /// Closes an uncertain attempt that provably never started a delivery.
    ///
    /// Requires the exact no-delivery evidence set: an expired effect window,
    /// no stream binding, no settlement and not one write-ahead journal record.
    /// A missing proof keeps the attempt untouched and reports a recovery
    /// conflict, so an uncertain delivery is never declared refused.
    ///
    /// # Errors
    ///
    /// Returns not-found, already-terminal, rejection-conflict, or recovery-
    /// conflict failures; none of them change the durable attempt.
    pub fn settle_uncertain_without_delivery(
        &self,
        attempt_id: DispatchAttemptId,
        rejection: ProviderPreEffectRejection,
        now_unix_seconds: u64,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        if record.state == ProviderDispatchState::RejectedBeforeEffect {
            return if record.pre_effect_rejection == Some(rejection) {
                Ok(ProviderDispatchState::RejectedBeforeEffect)
            } else {
                Err(ProviderStoreError::RejectionConflict)
            };
        }
        if record.state != ProviderDispatchState::Uncertain {
            return Err(ProviderStoreError::AlreadyTerminal);
        }
        if !no_delivery_evidence(&transaction, attempt_id, now_unix_seconds)?.proves_no_delivery() {
            return Err(ProviderStoreError::RecoveryConflict);
        }
        let changed = transaction
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 2, pre_effect_rejection = ?1
                 WHERE attempt_id = ?2 AND state = 6 AND stream_id IS NULL
                   AND settlement_digest IS NULL",
                params![
                    encode_pre_effect_rejection(rejection),
                    attempt_id.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        if changed != 1 {
            return Err(ProviderStoreError::CorruptData);
        }
        transaction
            .commit()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(ProviderDispatchState::RejectedBeforeEffect)
    }
}

#[cfg(test)]
mod no_delivery_tests {
    use super::*;

    const fn empty() -> NoDeliveryEvidence {
        NoDeliveryEvidence {
            uncertain: true,
            stream_unbound: true,
            unsettled: true,
            window_expired: true,
            journal_records: 0,
            poll_flights: 0,
            terminal_artifacts: 0,
            response_bindings: 0,
            operation_proofs: 0,
            unknown_receipts: 0,
            terminal_outbox: 0,
            terminal_settlements: 0,
        }
    }

    fn blocks(mutate: impl FnOnce(&mut NoDeliveryEvidence)) -> bool {
        let mut evidence = empty();
        mutate(&mut evidence);
        !evidence.proves_no_delivery()
    }

    #[test]
    fn no_delivery_requires_every_slot_clear() {
        assert!(empty().proves_no_delivery());
        assert!(blocks(|evidence| evidence.journal_records = 1));
        assert!(blocks(|evidence| evidence.terminal_artifacts = 1));
        assert!(blocks(|evidence| evidence.poll_flights = 1));
        assert!(blocks(|evidence| evidence.response_bindings = 1));
        assert!(blocks(|evidence| evidence.operation_proofs = 1));
        assert!(blocks(|evidence| evidence.unknown_receipts = 1));
        assert!(blocks(|evidence| evidence.terminal_outbox = 1));
        assert!(blocks(|evidence| evidence.terminal_settlements = 1));
        assert!(blocks(|evidence| evidence.uncertain = false));
        assert!(blocks(|evidence| evidence.stream_unbound = false));
        assert!(blocks(|evidence| evidence.unsettled = false));
        assert!(blocks(|evidence| evidence.window_expired = false));
    }
}
