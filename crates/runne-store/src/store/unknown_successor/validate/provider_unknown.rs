use super::fail;
use runne_application::ports::{CommitError, StorageFailureKind};
use runne_application::provider::ProviderRemoteAttemptBinding;
use runne_domain::id::{AttemptId, TaskRunId};
use runne_provider::ProviderRemoteResponseStatus;
use rusqlite::{Transaction, params};

pub(super) fn provider_unknown(
    tx: &Transaction<'_>,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) -> Result<([u8; 16], String, String, [u8; 32]), CommitError> {
    let row = tx
        .query_row(
            "SELECT i.dispatch_attempt_id,i.provider_id,i.profile_id,i.profile_digest,
                    i.pricing_revision_digest,i.credential_realm,i.semantic_digest,
                    i.prepared_digest,i.request_digest,i.runtime_authority_id,
                    i.database_generation,i.runtime_generation,i.fencing_token
             FROM provider_remote_request_intents i
             JOIN provider_execution_admissions a ON a.dispatch_attempt_id=i.dispatch_attempt_id
             JOIN provider_dispatch_attempts d ON d.attempt_id=i.dispatch_attempt_id
             JOIN provider_online_dispatch_claim_providers p
               ON p.dispatch_attempt_id=i.dispatch_attempt_id
             JOIN provider_online_credential_effect_bindings c
               ON c.dispatch_attempt_id=i.dispatch_attempt_id
             WHERE i.taskrun_id=?1 AND i.taskrun_attempt_id=?2
               AND (SELECT count(*) FROM provider_remote_request_intents j
                    WHERE j.taskrun_id=i.taskrun_id
                      AND j.taskrun_attempt_id=i.taskrun_attempt_id)=1
               AND a.taskrun_id=i.taskrun_id AND a.execution_attempt_id=i.taskrun_attempt_id
               AND a.profile_digest=i.profile_digest
               AND a.pricing_revision_digest=i.pricing_revision_digest
               AND a.semantic_digest=i.semantic_digest AND a.prepared_digest=i.prepared_digest
               AND a.render_digest=i.request_digest
               AND a.runtime_authority_id=i.runtime_authority_id
               AND a.database_generation=i.database_generation
               AND a.generation=i.runtime_generation AND a.fencing_token=i.fencing_token
               AND p.provider_id=i.provider_id AND c.provider_id=i.credential_realm
               AND d.state IN (4,6)
               AND NOT EXISTS(SELECT 1 FROM provider_terminal_dispositions t
                              WHERE t.dispatch_attempt_id=i.dispatch_attempt_id)
               AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t
                              WHERE t.dispatch_attempt_id=i.dispatch_attempt_id)
               AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_settlements s
                              WHERE s.dispatch_attempt_id=i.dispatch_attempt_id)",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .map_err(|_| fail(StorageFailureKind::PolicyDenied))?;
    let dispatch = parse_id(row.0)?;
    let profile_digest = parse_digest(row.3)?;
    let binding = ProviderRemoteAttemptBinding {
        taskrun_id,
        taskrun_attempt_id: attempt_id,
        dispatch_attempt_id: runne_provider::DispatchAttemptId::from_bytes(dispatch),
        provider_id: row.1.clone(),
        profile_id: row.2.clone(),
        profile_digest,
        pricing_digest: parse_digest(row.4)?,
        credential_realm: row.5.clone(),
        semantic_digest: parse_digest(row.6)?,
        prepared_digest: parse_digest(row.7)?,
        request_digest: parse_digest(row.8)?,
        runtime_authority_id: parse_id(row.9)?,
        database_generation: parse_u64(row.10)?,
        runtime_generation: parse_u64(row.11)?,
        fencing_token: parse_u64(row.12)?,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CommitError::ClockFailure)?;
    let now = i64::try_from(now.as_secs()).map_err(|_| CommitError::ClockFailure)?;
    let observation = crate::provider::read_remote_observation_in_transaction(tx, &binding, now)
        .map_err(|_| fail(StorageFailureKind::PolicyDenied))?;
    if observation.status == ProviderRemoteResponseStatus::Pending
        || matches!(
            observation.state,
            crate::provider::ProviderRemoteObservationState::Outstanding
                | crate::provider::ProviderRemoteObservationState::Pending
        )
    {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    Ok((dispatch, row.1, row.2, profile_digest))
}

fn parse_id(bytes: Vec<u8>) -> Result<[u8; 16], CommitError> {
    bytes
        .try_into()
        .map_err(|_| fail(StorageFailureKind::CorruptData))
}

fn parse_digest(bytes: Vec<u8>) -> Result<[u8; 32], CommitError> {
    bytes
        .try_into()
        .map_err(|_| fail(StorageFailureKind::CorruptData))
}

fn parse_u64(value: i64) -> Result<u64, CommitError> {
    u64::try_from(value).map_err(|_| fail(StorageFailureKind::CorruptData))
}
