impl SqliteIntentStore {
    /// Open a durable intent store using the canonical schema migrations.
    pub fn open(db_path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = schema::open_with_pragmas(&db_path.to_string_lossy())?;
        schema::apply_migrations(&conn)?;
        schema::run_startup_gates(&conn, &db_path.to_string_lossy())?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory intent store using the canonical schema migrations.
    #[doc(hidden)]
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        schema::apply_migrations(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Reserve an intent atomically. Exact duplicate requests replay the prior reservation.
    pub fn reserve(
        &self,
        intent_id: IntentID,
        key: &str,
        snapshot: VerificationDigest,
        target: VerificationDigest,
    ) -> Result<ConsumptionIntent, IntentError> {
        let mut conn = self.conn.lock().map_err(|_| IntentError::CorruptStore)?;
        let tx = immediate_transaction(&mut conn)?;

        let existing_by_id = find_intent(&tx, "intent_id", intent_id.as_bytes())?;
        let existing_by_key = find_intent(&tx, "idempotency_key", key)?;
        if let Some(existing) = existing_by_id.or(existing_by_key) {
            tx.commit().map_err(|_| IntentError::CorruptStore)?;
            if existing.intent_id == intent_id
                && existing.idempotency_key == key
                && existing.gate_head_snapshot_digest == snapshot
                && existing.target_artifact_digest == target
            {
                return Ok(existing);
            }
            return Err(IntentError::IdempotencyConflict);
        }

        let integrity = reservation_digest(&intent_id, key, &snapshot, &target);
        tx.execute(
            "INSERT INTO consumption_intents
             (intent_id, idempotency_key, state, gate_head_snapshot_digest,
              target_artifact_digest, integrity_digest)
             VALUES (?1, ?2, 'Reserved', ?3, ?4, ?5)",
            params![
                intent_id.as_bytes(),
                key,
                snapshot.as_bytes(),
                target.as_bytes(),
                integrity.as_bytes(),
            ],
        )
        .map_err(|_| IntentError::CorruptStore)?;
        tx.commit().map_err(|_| IntentError::CorruptStore)?;

        Ok(ConsumptionIntent {
            intent_id,
            idempotency_key: key.to_owned(),
            state: IntentState::Reserved,
            gate_head_snapshot_digest: snapshot,
            target_artifact_digest: target,
            integrity_digest: integrity,
        })
    }

    /// Atomically claim a reservation when its exact integrity digest still matches.
    pub fn claim_dispatching(
        &self,
        intent_id: &IntentID,
        expected_digest: &VerificationDigest,
    ) -> Result<(), IntentError> {
        let mut conn = self.conn.lock().map_err(|_| IntentError::CorruptStore)?;
        let tx = immediate_transaction(&mut conn)?;
        let intent = find_intent(&tx, "intent_id", intent_id.as_bytes())?
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state == IntentState::Invalidated {
            return Err(IntentError::IntentInvalidated);
        }
        if intent.state != IntentState::Reserved {
            return Err(IntentError::InvalidTransition);
        }
        if intent.integrity_digest != *expected_digest {
            return Err(IntentError::DigestMismatch);
        }
        let affected = tx
            .execute(
                "UPDATE consumption_intents SET state = 'Dispatching'
                 WHERE intent_id = ?1 AND state = 'Reserved' AND integrity_digest = ?2",
                params![intent_id.as_bytes(), expected_digest.as_bytes()],
            )
            .map_err(|_| IntentError::CorruptStore)?;
        if affected != 1 {
            return Err(IntentError::InvalidTransition);
        }
        tx.commit().map_err(|_| IntentError::CorruptStore)
    }

    /// Invalidate a reservation. Repeating the same invalidation is a deterministic replay.
    pub fn invalidate(&self, intent_id: &IntentID) -> Result<(), IntentError> {
        self.transition(intent_id, IntentState::Reserved, IntentState::Invalidated)
    }

    /// Settle a dispatch. Repeating the same terminal outcome is a deterministic replay.
    pub fn settle(&self, intent_id: &IntentID, success: bool) -> Result<(), IntentError> {
        self.transition(
            intent_id,
            IntentState::Dispatching,
            if success {
                IntentState::Completed
            } else {
                IntentState::Failed
            },
        )
    }

    /// Reconcile dispatch evidence without accepting contradictory terminal outcomes.
    pub fn reconcile(
        &self,
        intent_id: &IntentID,
        evidence: &DispatchEvidence,
    ) -> Result<(), IntentError> {
        match evidence {
            DispatchEvidence::NotStarted => {
                self.transition(intent_id, IntentState::Dispatching, IntentState::Abandoned)
            }
            DispatchEvidence::Acknowledged { outcome, .. } => self.transition(
                intent_id,
                IntentState::Dispatching,
                if outcome == "success" {
                    IntentState::Completed
                } else {
                    IntentState::Failed
                },
            ),
            DispatchEvidence::Unknown => {
                let mut conn = self.conn.lock().map_err(|_| IntentError::CorruptStore)?;
                let tx = immediate_transaction(&mut conn)?;
                let intent = find_intent(&tx, "intent_id", intent_id.as_bytes())?
                    .ok_or(IntentError::IntentNotFound)?;
                if intent.state != IntentState::Dispatching {
                    return Err(IntentError::InvalidTransition);
                }
                tx.commit().map_err(|_| IntentError::CorruptStore)
            }
        }
    }

    fn transition(
        &self,
        intent_id: &IntentID,
        from: IntentState,
        to: IntentState,
    ) -> Result<(), IntentError> {
        let mut conn = self.conn.lock().map_err(|_| IntentError::CorruptStore)?;
        let tx = immediate_transaction(&mut conn)?;
        let intent = find_intent(&tx, "intent_id", intent_id.as_bytes())?
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state == to {
            return tx.commit().map_err(|_| IntentError::CorruptStore);
        }
        if intent.state != from {
            return Err(IntentError::InvalidTransition);
        }
        let affected = tx
            .execute(
                "UPDATE consumption_intents SET state = ?1 WHERE intent_id = ?2 AND state = ?3",
                params![state_name(to), intent_id.as_bytes(), state_name(from)],
            )
            .map_err(|_| IntentError::CorruptStore)?;
        if affected != 1 {
            return Err(IntentError::InvalidTransition);
        }
        tx.commit().map_err(|_| IntentError::CorruptStore)
    }
}
