use super::*;

pub(super) fn parse_event_id(bytes: Vec<u8>) -> Result<EventId, EventStoreError> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| EventStoreError::CorruptData)?;
    let id = EventId::from_bytes(bytes);
    id.to_string()
        .parse::<EventId>()
        .map_err(|_| EventStoreError::CorruptData)
}

pub(super) fn parse_command_id(bytes: Vec<u8>) -> Result<CommandId, EventStoreError> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| EventStoreError::CorruptData)?;
    let id = CommandId::from_bytes(bytes);
    id.to_string()
        .parse::<CommandId>()
        .map_err(|_| EventStoreError::CorruptData)
}

pub(super) fn parse_integrity_digest(bytes: Vec<u8>) -> Result<IntegrityDigest, EventStoreError> {
    Ok(IntegrityDigest::from_bytes(
        bytes.try_into().map_err(|_| EventStoreError::CorruptData)?,
    ))
}

pub(super) fn parse_command_id_for_commit(bytes: Vec<u8>) -> Result<CommandId, CommitError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let id = CommandId::from_bytes(bytes);
    id.to_string()
        .parse::<CommandId>()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

pub(super) fn parse_event_id_for_commit(bytes: Vec<u8>) -> Result<EventId, CommitError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let id = EventId::from_bytes(bytes);
    id.to_string()
        .parse::<EventId>()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

pub(super) fn parse_fingerprint(bytes: Vec<u8>) -> Result<CommandFingerprint, CommitError> {
    Ok(CommandFingerprint::from_bytes(bytes.try_into().map_err(
        |_| storage_failure(StorageFailureKind::CorruptData),
    )?))
}

pub(super) const fn storage_failure(kind: StorageFailureKind) -> CommitError {
    CommitError::StorageFailure(kind)
}

pub(super) fn map_event_store_read_error(error: rusqlite::Error) -> EventStoreError {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            EventStoreError::Unavailable
        }
        _ => EventStoreError::CorruptData,
    }
}

pub(super) fn map_commit_read_error(error: rusqlite::Error) -> CommitError {
    let kind = match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            StorageFailureKind::Unavailable
        }
        _ => StorageFailureKind::CorruptData,
    };
    storage_failure(kind)
}

// ── UnitOfWork impl ──────────────────────────────────────────────────────
