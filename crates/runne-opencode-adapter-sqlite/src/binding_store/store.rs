impl SessionBindingStore for SqliteSessionBindingStore {
    fn ensure_pending(
        &self,
        key: &SessionBindingKey,
        context: &SessionBindingContext,
    ) -> Result<EnsurePendingResult, BindingError> {
        let snapshot = encode_context(context).map_err(|_| BindingError::SerializationFailed)?;
        let mut conn = self.connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::StorageFailure)?;
        if let Some(existing) = read_status(&tx, key)? {
            let exact = read_context(&tx, key)? == *context;
            if !exact {
                return Err(BindingError::Conflict(key.clone()));
            }
            return match existing.as_str() {
                "pending" => Ok(EnsurePendingResult::AlreadyPending),
                "committed" => Ok(EnsurePendingResult::AlreadyCommitted),
                _ => Err(BindingError::StorageFailure),
            };
        }
        validate_context_ids(context)?;
        let observed = self.inner.clock.now_millis()?.as_i64();
        let last: i64 = tx
            .query_row(
                "SELECT last_created_at FROM runne_session_binding_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| BindingError::StorageFailure)?;
        let created_at = observed.max(last.checked_add(1).ok_or(BindingError::StorageFailure)?);
        if tx
            .execute(
                "UPDATE runne_session_binding_state SET last_created_at=?1 WHERE singleton=1",
                params![created_at],
            )
            .map_err(|_| BindingError::StorageFailure)?
            != 1
        {
            return Err(BindingError::StorageFailure);
        }
        let result = tx.execute(
            "INSERT INTO session_bindings (session_id, profile_id, profile_revision, runtime_authority_id,
                conversation_id, workspace_id, command_id, idempotency_key, request_fingerprint,
                context_codec_version, context_snapshot, response_codec_version, response_snapshot, created_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, ?13, 'pending')",
            params![key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str(),
                context.conversation_id.as_bytes(), context.workspace_id.as_bytes(), context.command_id.as_bytes(),
                context.idempotency_key.as_str().as_bytes(), context.request_fingerprint.as_bytes(), i64::from(CODEC_VERSION), snapshot,
                i64::from(CODEC_VERSION), created_at],
        );
        match result {
            Ok(_) => {
                tx.commit().map_err(|_| BindingError::StorageFailure)?;
                self.harden_after_write()?;
                Ok(EnsurePendingResult::Created)
            }
            Err(error) if is_unique(&error) => Err(BindingError::Conflict(key.clone())),
            Err(_) => Err(BindingError::StorageFailure),
        }
    }

    fn commit(
        &self,
        key: &SessionBindingKey,
        expected_conversation_id: ConversationId,
        response: &OpenCodeSessionInfo,
    ) -> Result<(), BindingError> {
        let snapshot = encode_response(response).map_err(|_| BindingError::SerializationFailed)?;
        let mut conn = self.connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::StorageFailure)?;
        let row = read_row(&tx, key)?.ok_or_else(|| BindingError::NotFound(key.clone()))?;
        let context = decode_checked_context(&row, key)?;
        if context.conversation_id != expected_conversation_id {
            return Err(BindingError::Conflict(key.clone()));
        }
        match row.status.as_str() {
            "pending" => {
                if row.response.is_some() {
                    return Err(BindingError::StorageFailure);
                }
                let changes = tx.execute("UPDATE session_bindings SET status = 'committed', response_snapshot = ?1, response_codec_version = ?2
                    WHERE session_id = ?3 AND profile_id = ?4 AND profile_revision = ?5 AND runtime_authority_id = ?6 AND status = 'pending'",
                    params![snapshot, i64::from(CODEC_VERSION), key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str()])
                    .map_err(|_| BindingError::StorageFailure)?;
                if changes != 1 {
                    return Err(BindingError::Conflict(key.clone()));
                }
                tx.commit().map_err(|_| BindingError::StorageFailure)?;
                self.harden_after_write()
            }
            "committed" => {
                let existing = row.response.ok_or(BindingError::StorageFailure)?;
                decode_response(&existing).map_err(|_| BindingError::SerializationFailed)?;
                if existing == snapshot {
                    Ok(())
                } else {
                    Err(BindingError::Conflict(key.clone()))
                }
            }
            _ => Err(BindingError::StorageFailure),
        }
    }

    fn lookup(
        &self,
        key: &SessionBindingKey,
    ) -> Result<Option<SessionBindingStatus>, BindingError> {
        let conn = self.connection()?;
        let row = read_row(&*conn, key)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let context = decode_checked_context(&row, key)?;
        match row.status.as_str() {
            "pending" if row.response.is_none() => {
                Ok(Some(SessionBindingStatus::Pending { context }))
            }
            "committed" => Ok(Some(SessionBindingStatus::Committed {
                context,
                response: decode_response(&row.response.ok_or(BindingError::StorageFailure)?)
                    .map_err(|_| BindingError::SerializationFailed)?,
            })),
            _ => Err(BindingError::StorageFailure),
        }
    }

    fn list_pending(
        &self,
        authority: &BindingRuntimeAuthorityId,
        limit: usize,
        after: Option<&(NonNegativeUnixMillis, SessionBindingKey)>,
    ) -> Result<Vec<(NonNegativeUnixMillis, SessionBindingKey)>, BindingError> {
        if limit == 0 || limit > MAX_RECOVERY_PENDING_LIMIT {
            return Err(BindingError::InvalidLimit {
                max: MAX_RECOVERY_PENDING_LIMIT,
                actual: limit,
            });
        }
        if let Some((_, key)) = after
            && key.runtime_authority_id != *authority
        {
            return Err(BindingError::Conflict(key.clone()));
        }
        let mut conn = self.connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::StorageFailure)?;
        if let Some((time, key)) = after {
            let cursor = tx.query_row("SELECT status, created_at FROM session_bindings WHERE session_id=?1 AND profile_id=?2 AND profile_revision=?3 AND runtime_authority_id=?4", params![key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))).optional().map_err(|_| BindingError::StorageFailure)?;
            if cursor != Some(("pending".to_owned(), time.as_i64())) {
                return Err(BindingError::Conflict(key.clone()));
            }
        }
        let mut statement = tx.prepare(
            "SELECT created_at, session_id, profile_id, profile_revision, runtime_authority_id
             FROM session_bindings WHERE runtime_authority_id = ?1 AND status = 'pending'
             AND (?2 IS NULL OR created_at > ?2 OR (created_at = ?2 AND (session_id > ?3 OR
                (session_id = ?3 AND (profile_id > ?4 OR (profile_id = ?4 AND (profile_revision > ?5 OR
                (profile_revision = ?5 AND runtime_authority_id > ?6))))))))
             ORDER BY created_at, session_id, profile_id, profile_revision, runtime_authority_id LIMIT ?7"
        ).map_err(|_| BindingError::StorageFailure)?;
        let (timestamp, key) =
            after.map_or((None, None), |(time, key)| (Some(time.as_i64()), Some(key)));
        let rows = statement
            .query_map(
                params![
                    authority.as_str(),
                    timestamp,
                    key.map(|k| k.session_id.as_str()),
                    key.map(|k| k.profile_id.as_str()),
                    key.map(|k| i64::from(k.profile_revision)),
                    key.map(|k| k.runtime_authority_id.as_str()),
                    i64::try_from(limit).map_err(|_| BindingError::StorageFailure)?
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .map_err(|_| BindingError::StorageFailure)?;
        let mut output = Vec::new();
        for row in rows {
            let (created, session_id, profile_id, revision, runtime_authority_id) =
                row.map_err(|_| BindingError::StorageFailure)?;
            let time = NonNegativeUnixMillis::new(created).ok_or(BindingError::StorageFailure)?;
            let key = make_key(session_id, profile_id, revision, runtime_authority_id)?;
            output.push((time, key));
        }
        drop(statement);
        tx.commit().map_err(|_| BindingError::StorageFailure)?;
        Ok(output)
    }
}
