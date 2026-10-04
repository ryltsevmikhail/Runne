fn read_remote_terminal_artifact(
    store: &SqliteProviderExecutionStore,
    attempt: DispatchAttemptId,
) -> Result<Option<ProviderRemoteTerminalRecord>, ProviderExecutionError> {
    let connection = store
        .connection
        .lock()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    read_remote_terminal_artifact_from(&connection, attempt)
}

fn read_remote_attempt_snapshot(
    store: &SqliteProviderExecutionStore,
    attempt: DispatchAttemptId,
) -> Result<Option<ProviderRemoteAttemptRecord>, ProviderExecutionError> {
    let mut connection = store
        .connection
        .lock()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let record = read_remote_attempt_in_transaction(&tx, attempt)?;
    tx.commit()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    Ok(record)
}

pub(crate) fn read_remote_attempt_in_transaction(
    connection: &rusqlite::Connection,
    attempt: DispatchAttemptId,
) -> Result<Option<ProviderRemoteAttemptRecord>, ProviderExecutionError> {
    let request = load_remote_request(connection, attempt)?;
    let Some(request) = request else {
        return Ok(None);
    };
    let response = load_remote_response(connection, attempt)?;
    let terminal = read_remote_terminal_artifact_from(connection, attempt)?;
    Ok(Some(ProviderRemoteAttemptRecord {
        request,
        response,
        terminal,
    }))
}

pub(crate) fn verify_remote_unknown_in_transaction(
    connection: &rusqlite::Connection,
    expected: &runne_application::provider::ProviderRemoteAttemptBinding,
) -> Result<(), ProviderExecutionError> {
    let record = read_remote_attempt_in_transaction(connection, expected.dispatch_attempt_id)?
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    if record.terminal.is_some() || record.request.binding != *expected
        || record.response.as_ref().is_some_and(|response| response.binding != *expected)
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}

/// Fresh bounded nonterminal fact from the latest consumed status/cancel proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProviderRemoteObservationState {
    None,
    Outstanding,
    Pending,
    Unknown,
    Expired,
    Stale,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProviderRemoteObservationFact {
    pub(crate) status: runne_provider::ProviderRemoteResponseStatus,
    pub(crate) observed_at: u64,
    pub(crate) state: ProviderRemoteObservationState,
}

/// Reads one exact attempt's latest nonterminal observation in the caller's snapshot.
/// Observations older than ten minutes, or hidden by an outstanding/expired proof,
/// are conservatively reported as Unknown.
pub(crate) fn read_remote_observation_in_transaction(
    connection: &rusqlite::Connection,
    expected: &runne_application::provider::ProviderRemoteAttemptBinding,
    now: i64,
) -> Result<ProviderRemoteObservationFact, ProviderExecutionError> {
    verify_remote_unknown_in_transaction(connection, expected)?;
    let latest: Option<(i64, Option<i64>, Option<i64>, i64)> = connection.query_row(
        "SELECT state,observation_status,observed_at,expires_at FROM provider_remote_operation_proofs
         WHERE dispatch_attempt_id=?1 ORDER BY issued_at DESC,rowid DESC LIMIT 1",
        [expected.dispatch_attempt_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let (status, observed_at, state) = match latest {
        None => (runne_provider::ProviderRemoteResponseStatus::Unknown, 0,
            ProviderRemoteObservationState::None),
        Some((1, _, _, expires_at)) if now >= 0 && now < expires_at => {
            let previous: Option<(Option<i64>, Option<i64>)> = connection.query_row(
                "SELECT observation_status,observed_at FROM provider_remote_operation_proofs
                 WHERE dispatch_attempt_id=?1 AND state=2 AND observation_status IS NOT NULL
                 ORDER BY issued_at DESC,rowid DESC LIMIT 1",
                [expected.dispatch_attempt_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            match previous {
                Some((Some(1), Some(observed))) if fresh_observation(now, observed) =>
                    (runne_provider::ProviderRemoteResponseStatus::Pending,
                     u64::try_from(observed).unwrap_or(0), ProviderRemoteObservationState::Outstanding),
                _ => (runne_provider::ProviderRemoteResponseStatus::Unknown, 0,
                    ProviderRemoteObservationState::Outstanding),
            }
        }
        Some((1, _, _, _)) | Some((3, _, _, _)) =>
            (runne_provider::ProviderRemoteResponseStatus::Unknown, 0,
            ProviderRemoteObservationState::Expired),
        Some((2, Some(1), Some(observed), _)) if fresh_observation(now, observed) =>
            (runne_provider::ProviderRemoteResponseStatus::Pending,
             u64::try_from(observed).unwrap_or(0), ProviderRemoteObservationState::Pending),
        Some((2, Some(2), Some(observed), _)) if fresh_observation(now, observed) =>
            (runne_provider::ProviderRemoteResponseStatus::Unknown,
             u64::try_from(observed).unwrap_or(0), ProviderRemoteObservationState::Unknown),
        _ => (runne_provider::ProviderRemoteResponseStatus::Unknown, 0,
            ProviderRemoteObservationState::Stale),
    };
    Ok(ProviderRemoteObservationFact { status, observed_at, state })
}

fn fresh_observation(now: i64, observed: i64) -> bool {
    now >= observed && now.checked_sub(observed).is_some_and(|age| age <= 600)
}

fn read_remote_terminal_artifact_from(
    connection: &rusqlite::Connection,
    attempt: DispatchAttemptId,
) -> Result<Option<ProviderRemoteTerminalRecord>, ProviderExecutionError> {
    let row: Option<TerminalArtifactRow> = connection.query_row(
        "SELECT taskrun_id,taskrun_attempt_id,provider_id,profile_id,profile_digest,pricing_revision_digest,
           credential_realm,request_digest,runtime_authority_id,database_generation,runtime_generation,
           fencing_token,key_id,key_version,response_id_digest,nonce,ciphertext,plaintext_len,plaintext_digest,
           disposition,semantic_digest,prepared_digest
         FROM provider_remote_terminal_artifacts WHERE dispatch_attempt_id=?1",
        [attempt.as_bytes().as_slice()], TerminalArtifactRow::read,
    ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    row.map(|row| row.decode(attempt)).transpose()
}

struct TerminalArtifactRow {
    taskrun: Vec<u8>,
    task_attempt: Vec<u8>,
    provider: String,
    profile: String,
    profile_digest: Vec<u8>,
    pricing_digest: Vec<u8>,
    realm: String,
    request_digest: Vec<u8>,
    authority: Vec<u8>,
    db_generation: i64,
    generation: i64,
    fence: i64,
    key_id: Vec<u8>,
    key_version: i64,
    response_digest: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    plaintext_len: i64,
    plaintext_digest: Vec<u8>,
    disposition: i64,
    semantic_digest: Vec<u8>,
    prepared_digest: Vec<u8>,
}

impl TerminalArtifactRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            taskrun: row.get(0)?,
            task_attempt: row.get(1)?,
            provider: row.get(2)?,
            profile: row.get(3)?,
            profile_digest: row.get(4)?,
            pricing_digest: row.get(5)?,
            realm: row.get(6)?,
            request_digest: row.get(7)?,
            authority: row.get(8)?,
            db_generation: row.get(9)?,
            generation: row.get(10)?,
            fence: row.get(11)?,
            key_id: row.get(12)?,
            key_version: row.get(13)?,
            response_digest: row.get(14)?,
            nonce: row.get(15)?,
            ciphertext: row.get(16)?,
            plaintext_len: row.get(17)?,
            plaintext_digest: row.get(18)?,
            disposition: row.get(19)?,
            semantic_digest: row.get(20)?,
            prepared_digest: row.get(21)?,
        })
    }

    fn decode(
        self,
        attempt: DispatchAttemptId,
    ) -> Result<ProviderRemoteTerminalRecord, ProviderExecutionError> {
        use runne_domain::id::{AttemptId, TaskRunId};
        let binding = ProviderRemoteAttemptBinding {
            taskrun_id: TaskRunId::from_bytes(remote_fixed(self.taskrun)?),
            taskrun_attempt_id: AttemptId::from_bytes(remote_fixed(self.task_attempt)?),
            dispatch_attempt_id: attempt,
            provider_id: self.provider,
            credential_realm: self.realm,
            profile_id: self.profile,
            profile_digest: remote_fixed(self.profile_digest)?,
            pricing_digest: remote_fixed(self.pricing_digest)?,
            semantic_digest: remote_fixed(self.semantic_digest)?,
            prepared_digest: remote_fixed(self.prepared_digest)?,
            request_digest: remote_fixed(self.request_digest)?,
            runtime_authority_id: remote_fixed(self.authority)?,
            database_generation: remote_positive(self.db_generation)?,
            runtime_generation: remote_positive(self.generation)?,
            fencing_token: remote_positive(self.fence)?,
        };
        let disposition = match self.disposition {
            1 => ProviderRemoteTerminalDisposition::Completed,
            2 => ProviderRemoteTerminalDisposition::Failed,
            3 => ProviderRemoteTerminalDisposition::Incomplete,
            5 => ProviderRemoteTerminalDisposition::Cancelled,
            _ => return Err(ProviderExecutionError::JournalCorrupt),
        };
        let encrypted = ProviderEncryptedPayload::new(
            remote_fixed(self.nonce)?,
            self.ciphertext,
            remote_positive(self.plaintext_len)?,
            remote_fixed(self.plaintext_digest)?,
        )?;
        let key = ProviderJournalKeyBinding::new(
            remote_fixed(self.key_id)?,
            remote_positive(self.key_version)?,
            binding.runtime_authority_id,
            binding.database_generation,
        )?;
        ProviderRemoteTerminalRecord::new(
            binding,
            key,
            remote_fixed(self.response_digest)?,
            disposition,
            encrypted,
        )
    }
}

fn remote_fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], ProviderExecutionError> {
    bytes
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn remote_positive(value: i64) -> Result<u64, ProviderExecutionError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ProviderExecutionError::JournalCorrupt)
}
