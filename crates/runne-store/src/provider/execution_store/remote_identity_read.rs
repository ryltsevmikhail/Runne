fn load_remote_request(
    connection: &Connection,
    attempt: DispatchAttemptId,
) -> Result<Option<ProviderRemoteRequestIntent>, ProviderExecutionError> {
    let row = connection.query_row(
        "SELECT taskrun_id,taskrun_attempt_id,provider_id,profile_id,profile_digest,
         pricing_revision_digest,credential_realm,semantic_digest,prepared_digest,request_digest,
         runtime_authority_id,database_generation,runtime_generation,fencing_token,key_id,key_version,
         nonce,ciphertext,plaintext_len,plaintext_digest FROM provider_remote_request_intents
         WHERE dispatch_attempt_id=?1", [attempt.as_bytes().as_slice()], read_remote_row,
    ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    row.map(|parts| request_from_row(attempt, parts))
        .transpose()
}

type RemoteRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
);
fn read_remote_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RemoteRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
        row.get(19)?,
    ))
}

fn request_from_row(
    attempt: DispatchAttemptId,
    r: RemoteRow,
) -> Result<ProviderRemoteRequestIntent, ProviderExecutionError> {
    let binding = binding_from_row(attempt, &r)?;
    let key = remote_key(&r)?;
    let encrypted = remote_payload(&r)?;
    Ok(ProviderRemoteRequestIntent {
        binding,
        key,
        encrypted_request: encrypted,
    })
}

fn binding_from_row(
    attempt: DispatchAttemptId,
    r: &RemoteRow,
) -> Result<ProviderRemoteAttemptBinding, ProviderExecutionError> {
    use runne_domain::id::{AttemptId, TaskRunId};
    let bytes16 =
        |v: &[u8]| <[u8; 16]>::try_from(v).map_err(|_| ProviderExecutionError::JournalCorrupt);
    let bytes32 =
        |v: &[u8]| <[u8; 32]>::try_from(v).map_err(|_| ProviderExecutionError::JournalCorrupt);
    Ok(ProviderRemoteAttemptBinding {
        taskrun_id: TaskRunId::from_bytes(bytes16(&r.0)?),
        taskrun_attempt_id: AttemptId::from_bytes(bytes16(&r.1)?),
        dispatch_attempt_id: attempt,
        provider_id: r.2.clone(),
        profile_id: r.3.clone(),
        profile_digest: bytes32(&r.4)?,
        pricing_digest: bytes32(&r.5)?,
        semantic_digest: bytes32(&r.7)?,
        credential_realm: r.6.clone(),
        prepared_digest: bytes32(&r.8)?,
        request_digest: bytes32(&r.9)?,
        runtime_authority_id: bytes16(&r.10)?,
        database_generation: nonnegative(r.11)?,
        runtime_generation: nonnegative(r.12)?,
        fencing_token: nonnegative(r.13)?,
    })
}

fn remote_key(r: &RemoteRow) -> Result<ProviderJournalKeyBinding, ProviderExecutionError> {
    let key_id = <[u8; 16]>::try_from(r.14.as_slice())
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    ProviderJournalKeyBinding::new(
        key_id,
        nonnegative(r.15)?,
        <[u8; 16]>::try_from(r.10.as_slice())
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        nonnegative(r.11)?,
    )
}

fn remote_payload(r: &RemoteRow) -> Result<ProviderEncryptedPayload, ProviderExecutionError> {
    ProviderEncryptedPayload::new(
        <[u8; 12]>::try_from(r.16.as_slice())
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        r.17.clone(),
        nonnegative(r.18)?,
        <[u8; 32]>::try_from(r.19.as_slice())
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
    )
}

fn load_remote_response(
    connection: &Connection,
    attempt: DispatchAttemptId,
) -> Result<Option<ProviderRemoteIdentityRecord>, ProviderExecutionError> {
    let exact: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_remote_response_bindings r
         JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
         WHERE r.dispatch_attempt_id=?1 AND r.taskrun_id=q.taskrun_id
           AND r.taskrun_attempt_id=q.taskrun_attempt_id AND r.provider_id=q.provider_id
           AND r.profile_id=q.profile_id AND r.profile_digest=q.profile_digest
           AND r.pricing_revision_digest=q.pricing_revision_digest
           AND r.credential_realm=q.credential_realm AND r.request_digest=q.request_digest
           AND r.runtime_authority_id=q.runtime_authority_id
           AND r.database_generation=q.database_generation
           AND r.runtime_generation=q.runtime_generation AND r.fencing_token=q.fencing_token
           AND r.key_id=q.key_id AND r.key_version=q.key_version)",
            [attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_remote_response_bindings WHERE dispatch_attempt_id=?1)",
        [attempt.as_bytes().as_slice()], |row| row.get(0),
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if exists && !exact {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    if !exists {
        return Ok(None);
    }
    let payload = connection.query_row("SELECT key_id,key_version,nonce,ciphertext,plaintext_len,plaintext_digest FROM provider_remote_response_bindings WHERE dispatch_attempt_id=?1", [attempt.as_bytes().as_slice()], |row| {
        Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,i64>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,i64>(4)?,row.get::<_,Vec<u8>>(5)?))
    }).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let Some(payload) = payload else {
        return Err(ProviderExecutionError::JournalCorrupt);
    };
    let request =
        load_remote_request(connection, attempt)?.ok_or(ProviderExecutionError::JournalCorrupt)?;
    let key_id = <[u8; 16]>::try_from(payload.0.as_slice())
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let key = ProviderJournalKeyBinding::new(
        key_id,
        nonnegative(payload.1)?,
        request.binding.runtime_authority_id,
        request.binding.database_generation,
    )
    .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let encrypted_response_id = ProviderEncryptedPayload::new(
        <[u8; 12]>::try_from(payload.2.as_slice())
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        payload.3,
        nonnegative(payload.4)?,
        <[u8; 32]>::try_from(payload.5.as_slice())
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
    )?;
    Ok(Some(ProviderRemoteIdentityRecord {
        binding: request.binding,
        key,
        encrypted_response_id,
    }))
}

fn nonnegative(value: i64) -> Result<u64, ProviderExecutionError> {
    u64::try_from(value).map_err(|_| ProviderExecutionError::JournalCorrupt)
}
