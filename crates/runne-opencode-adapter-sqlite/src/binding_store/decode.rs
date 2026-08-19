struct RowData {
    status: String,
    conversation: Vec<u8>,
    workspace: Vec<u8>,
    command: Vec<u8>,
    idempotency: Vec<u8>,
    fingerprint: Vec<u8>,
    context_version: i64,
    context: Vec<u8>,
    response_version: i64,
    response: Option<Vec<u8>>,
}
fn read_status(
    tx: &Transaction<'_>,
    key: &SessionBindingKey,
) -> Result<Option<String>, BindingError> {
    tx.query_row("SELECT status FROM session_bindings WHERE session_id=?1 AND profile_id=?2 AND profile_revision=?3 AND runtime_authority_id=?4", params![key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str()], |row| row.get(0)).optional().map_err(|_| BindingError::StorageFailure)
}
fn read_context(
    tx: &Transaction<'_>,
    key: &SessionBindingKey,
) -> Result<SessionBindingContext, BindingError> {
    let row = read_row(tx, key)?.ok_or_else(|| BindingError::NotFound(key.clone()))?;
    decode_checked_context(&row, key)
}
fn read_row(query: &impl Query, key: &SessionBindingKey) -> Result<Option<RowData>, BindingError> {
    query.query_row("SELECT status,conversation_id,workspace_id,command_id,idempotency_key,request_fingerprint,context_codec_version,context_snapshot,response_codec_version,response_snapshot FROM session_bindings WHERE session_id=?1 AND profile_id=?2 AND profile_revision=?3 AND runtime_authority_id=?4", params![key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str()], |r| Ok(RowData { status:r.get(0)?, conversation:r.get(1)?, workspace:r.get(2)?, command:r.get(3)?, idempotency:r.get(4)?, fingerprint:r.get(5)?, context_version:r.get(6)?, context:r.get(7)?, response_version:r.get(8)?, response:r.get(9)? })).optional().map_err(|_| BindingError::StorageFailure)
}
fn decode_checked_context(
    row: &RowData,
    _key: &SessionBindingKey,
) -> Result<SessionBindingContext, BindingError> {
    if row.context_version != i64::from(CODEC_VERSION)
        || row.response_version != i64::from(CODEC_VERSION)
        || row.fingerprint.len() != 32
    {
        return Err(BindingError::SerializationFailed);
    }
    let context = decode_context(&row.context).map_err(|_| BindingError::SerializationFailed)?;
    if row.conversation != context.conversation_id.as_bytes()
        || row.workspace != context.workspace_id.as_bytes()
        || row.command != context.command_id.as_bytes()
        || row.idempotency != context.idempotency_key.as_str().as_bytes()
        || row.fingerprint != context.request_fingerprint.as_bytes()
    {
        return Err(BindingError::SerializationFailed);
    }
    Ok(context)
}
fn validate_context_ids(context: &SessionBindingContext) -> Result<(), BindingError> {
    runne_domain::id::ConversationId::from_str(&context.conversation_id.to_string())
        .and_then(|id| {
            if id == context.conversation_id {
                Ok(id)
            } else {
                Err(runne_domain::id::InvalidIdReason::InvalidUuidFormat)
            }
        })
        .map_err(|_| BindingError::SerializationFailed)?;
    runne_domain::id::WorkspaceId::from_str(&context.workspace_id.to_string())
        .map_err(|_| BindingError::SerializationFailed)?;
    runne_domain::id::CommandId::from_str(&context.command_id.to_string())
        .map_err(|_| BindingError::SerializationFailed)?;
    Ok(())
}
fn make_key(
    session_id: String,
    profile_id: String,
    revision: i64,
    authority: String,
) -> Result<SessionBindingKey, BindingError> {
    Ok(SessionBindingKey {
        session_id: runne_opencode_compat::OpenCodeSessionId::new(session_id)
            .map_err(|_| BindingError::SerializationFailed)?,
        profile_id: runne_opencode_compat::profile::ProfileId::new(profile_id)
            .map_err(|_| BindingError::SerializationFailed)?,
        profile_revision: u16::try_from(revision).map_err(|_| BindingError::SerializationFailed)?,
        runtime_authority_id: BindingRuntimeAuthorityId::new(authority)
            .map_err(|_| BindingError::SerializationFailed)?,
    })
}
fn is_unique(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::SqliteFailure(code, _) if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY || code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
}
