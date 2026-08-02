impl ReplayService {
    fn cursor_message(cursor: &ReplayCursor) -> Result<Vec<u8>, ReplayError> {
        let event_type = cursor.event_type.as_bytes();
        if event_type.is_empty()
            || event_type.len() > MAX_EVENT_TYPE_BYTES
            || event_type.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(ReplayError::CursorInvalid {
                reason: "invalid cursor event type".to_owned(),
            });
        }
        let event_type_len =
            u16::try_from(event_type.len()).map_err(|_| ReplayError::CursorInvalid {
                reason: "invalid cursor event type".to_owned(),
            })?;
        let mut message =
            Vec::with_capacity(16 + 1 + 16 + 8 + 8 + 16 + 32 + 4 + 1 + 2 + event_type.len());
        message.extend_from_slice(cursor.event_id.as_bytes());
        message.push(match &cursor.aggregate_id {
            AggregateId::TaskRun(_) => 1,
            AggregateId::Conversation(_) => 2,
            AggregateId::Workspace(_) => 3,
        });
        match &cursor.aggregate_id {
            AggregateId::TaskRun(id) => message.extend_from_slice(id.as_bytes()),
            AggregateId::Conversation(id) => message.extend_from_slice(id.as_bytes()),
            AggregateId::Workspace(id) => message.extend_from_slice(id.as_bytes()),
        }
        message.extend_from_slice(&cursor.sequence.to_be_bytes());
        message.extend_from_slice(&cursor.global_position.to_be_bytes());
        message.extend_from_slice(cursor.lineage_id.as_bytes());
        message.extend_from_slice(&cursor.scope.canonical_digest());
        message.extend_from_slice(&cursor.schema_version.to_be_bytes());
        message.push(match cursor.sensitivity {
            Sensitivity::Public => 0,
            Sensitivity::Internal => 1,
            Sensitivity::Sensitive => 2,
        });
        message.extend_from_slice(&event_type_len.to_be_bytes());
        message.extend_from_slice(event_type);
        Ok(message)
    }

    /// Строит ackable cursor из delivered event и границ session.
    fn build_cursor(
        &self,
        event: &ReplayEvent,
        scope: &ReplayScope,
    ) -> Result<ReplayCursor, ReplayError> {
        if event.global_position <= 0
            || event.sequence <= 0
            || event.schema_version == 0
            || event.event_type.is_empty()
            || event.event_type.len() > MAX_EVENT_TYPE_BYTES
            || event
                .event_type
                .as_bytes()
                .iter()
                .any(|byte| byte.is_ascii_control())
            || !matches!(
                scope,
                ReplayScope::Aggregate {
                    aggregate_type,
                    aggregate_id,
                } if i32::from(*aggregate_type) == event.aggregate_type
                    && aggregate_id == &event.aggregate_id
            )
        {
            return Err(ReplayError::Integrity(
                "invalid delivered replay event metadata".to_owned(),
            ));
        }
        let aggregate_id = match event.aggregate_type {
            1 => AggregateId::TaskRun(TaskRunId::from_bytes(event.aggregate_id)),
            2 => AggregateId::Conversation(ConversationId::from_bytes(event.aggregate_id)),
            _ => {
                return Err(ReplayError::Integrity(
                    "unsupported delivered replay aggregate".to_owned(),
                ));
            }
        };
        let sensitivity = match event.sensitivity {
            0 => Sensitivity::Public,
            1 => Sensitivity::Internal,
            2 => Sensitivity::Sensitive,
            _ => {
                return Err(ReplayError::Integrity(
                    "invalid delivered replay sensitivity".to_owned(),
                ));
            }
        };
        let mut cursor = ReplayCursor {
            event_id: EventId::from_bytes(event.event_id),
            aggregate_id,
            sequence: u64::try_from(event.sequence).map_err(|_| {
                ReplayError::Integrity("invalid delivered replay sequence".to_owned())
            })?,
            global_position: event.global_position,
            lineage_id: self.lineage_id,
            scope: scope.clone(),
            schema_version: CURSOR_SCHEMA_VERSION,
            sensitivity,
            event_type: event.event_type.clone(),
            integrity: IntegrityDigest::from_bytes([0; 32]),
        };
        let mut mac = HmacSha256::new_from_slice(&self.server_secret).expect("fixed HMAC key size");
        mac.update(&Self::cursor_message(&cursor)?);
        cursor.integrity = IntegrityDigest::from_bytes(mac.finalize().into_bytes().into());
        Ok(cursor)
    }

    /// Проверяет integrity cursor относительно server secret.
    pub fn validate_cursor_integrity(&self, cursor: &ReplayCursor) -> Result<(), ReplayError> {
        if cursor.schema_version != CURSOR_SCHEMA_VERSION {
            return Err(ReplayError::CursorInvalid {
                reason: "unsupported cursor schema".to_string(),
            });
        }
        if cursor.lineage_id != self.lineage_id {
            return Err(ReplayError::CursorInvalid {
                reason: "event log lineage mismatch".to_string(),
            });
        }
        let mut mac = HmacSha256::new_from_slice(&self.server_secret).expect("fixed HMAC key size");
        mac.update(&Self::cursor_message(cursor)?);
        mac.verify_slice(cursor.integrity.as_bytes())
            .map_err(|_| ReplayError::CursorInvalid {
                reason: "cursor integrity mismatch".to_string(),
            })
    }

    /// Публичный helper для transport adapter, формирующий cursor delivered event.
    pub fn build_cursor_from_event(
        &self,
        event: &ReplayEvent,
        scope: &ReplayScope,
    ) -> Result<ReplayCursor, ReplayError> {
        self.build_cursor(event, scope)
    }

}
