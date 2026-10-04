struct V62AuditRow {
    fields: V62AuditDigestFields,
    taskrun: Vec<u8>,
    attempt: Vec<u8>,
    conversation: Vec<u8>,
    terminal_event: Option<Vec<u8>>,
    terminal_version: Option<i64>,
    successor: Option<Vec<u8>>,
    successor_submit: Option<Vec<u8>>,
    successor_submit_version: Option<i64>,
    supersession: Option<Vec<u8>>,
    release_event: Vec<u8>,
    release_version: i64,
    release_fence: i64,
    reason: String,
    acknowledgement: Option<Vec<u8>>,
    conversation_event: Vec<u8>,
    conversation_version: i64,
    digest: Vec<u8>,
}

fn read_v62_audit_row(row: &rusqlite::Row<'_>) -> SqliteResult<V62AuditRow> {
    let dispatch: Vec<u8> = row.get(0)?;
    let taskrun: Vec<u8> = row.get(1)?;
    let attempt: Vec<u8> = row.get(2)?;
    let conversation: Vec<u8> = row.get(3)?;
    let request: Vec<u8> = row.get(4)?;
    let response: Vec<u8> = row.get(5)?;
    let artifact: Vec<u8> = row.get(6)?;
    let terminal_status: i64 = row.get(7)?;
    let witness_kind: i64 = row.get(8)?;
    let terminal_event: Option<Vec<u8>> = row.get(9)?;
    let terminal_version: Option<i64> = row.get(10)?;
    let successor: Option<Vec<u8>> = row.get(11)?;
    let successor_submit: Option<Vec<u8>> = row.get(12)?;
    let successor_submit_version: Option<i64> = row.get(13)?;
    let supersession: Option<Vec<u8>> = row.get(14)?;
    let supersession_version: Option<i64> = row.get(15)?;
    let release_event: Vec<u8> = row.get(16)?;
    let release_version: i64 = row.get(17)?;
    let release_fence: i64 = row.get(18)?;
    let reason: String = row.get(19)?;
    let acknowledgement: Option<Vec<u8>> = row.get(20)?;
    let conversation_event: Vec<u8> = row.get(21)?;
    let conversation_version: i64 = row.get(22)?;
    let accounting_state: i64 = row.get(23)?;
    let accounting_digest: Option<Vec<u8>> = row.get(24)?;
    let digest: Vec<u8> = row.get(25)?;
    let fixed16 = |value: &[u8]| <[u8; 16]>::try_from(value).ok();
    let fixed32 = |value: &[u8]| <[u8; 32]>::try_from(value).ok();
    let optional16 = |value: &Option<Vec<u8>>| -> SqliteResult<Option<[u8; 16]>> {
        value
            .as_deref()
            .map(|bytes| fixed16(bytes).ok_or(rusqlite::Error::InvalidQuery))
            .transpose()
    };
    let optional32 = |value: &Option<Vec<u8>>| -> SqliteResult<Option<[u8; 32]>> {
        value
            .as_deref()
            .map(|bytes| fixed32(bytes).ok_or(rusqlite::Error::InvalidQuery))
            .transpose()
    };
    let fields = V62AuditDigestFields {
        dispatch: fixed16(&dispatch).ok_or(rusqlite::Error::InvalidQuery)?,
        taskrun: fixed16(&taskrun).ok_or(rusqlite::Error::InvalidQuery)?,
        attempt: fixed16(&attempt).ok_or(rusqlite::Error::InvalidQuery)?,
        conversation: fixed16(&conversation).ok_or(rusqlite::Error::InvalidQuery)?,
        request: fixed32(&request).ok_or(rusqlite::Error::InvalidQuery)?,
        response: fixed32(&response).ok_or(rusqlite::Error::InvalidQuery)?,
        artifact: fixed32(&artifact).ok_or(rusqlite::Error::InvalidQuery)?,
        terminal_status,
        witness_kind,
        terminal_event: optional16(&terminal_event)?,
        terminal_version,
        successor_taskrun: optional16(&successor)?,
        successor_submit_event: optional16(&successor_submit)?,
        successor_submit_version,
        supersession_event: optional16(&supersession)?,
        supersession_version,
        release_event: fixed16(&release_event).ok_or(rusqlite::Error::InvalidQuery)?,
        release_version,
        release_fence,
        release_reason: reason.clone(),
        acknowledgement: optional32(&acknowledgement)?,
        conversation_observed_event: fixed16(&conversation_event)
            .ok_or(rusqlite::Error::InvalidQuery)?,
        conversation_observed_version: conversation_version,
        accounting_state,
        accounting_digest: optional32(&accounting_digest)?,
    };
    Ok(V62AuditRow {
        fields,
        taskrun,
        attempt,
        conversation,
        terminal_event,
        terminal_version,
        successor,
        successor_submit,
        successor_submit_version,
        supersession,
        release_event,
        release_version,
        release_fence,
        reason,
        acknowledgement,
        conversation_event,
        conversation_version,
        digest,
    })
}
