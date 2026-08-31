use runne_provider::{CredentialLifecycleError, CredentialVersionRef, ProviderId};
use rusqlite::{Connection, OptionalExtension, types::Value};

use super::rows::map_sql;

pub(super) struct Head {
    pub(super) lifecycle: i64,
    pub(super) fence: i64,
    pub(super) readiness: i64,
    pub(super) next_version: i64,
    pub(super) active: Option<CredentialVersionRef>,
    pub(super) hard_fenced: bool,
    pub(super) observed_at: i64,
}

pub(super) fn load_head(
    connection: &Connection,
    provider: &ProviderId,
) -> Result<Option<Head>, CredentialLifecycleError> {
    let raw = connection
        .query_row(
            "SELECT provider_id, lifecycle_revision, credential_fence, readiness_revision,
                    next_credential_version, active_credential_version, active_ref_digest,
                    hard_fence_disposition, observed_at_high_water
             FROM provider_credential_authority_heads WHERE provider_id=?1",
            [provider.as_str()],
            |row| {
                Ok((
                    row.get::<_, Value>(0)?,
                    row.get::<_, Value>(1)?,
                    row.get::<_, Value>(2)?,
                    row.get::<_, Value>(3)?,
                    row.get::<_, Value>(4)?,
                    row.get::<_, Value>(5)?,
                    row.get::<_, Value>(6)?,
                    row.get::<_, Value>(7)?,
                    row.get::<_, Value>(8)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql)?;
    raw.map(|raw| decode_head(provider, raw)).transpose()
}

type RawHead = (
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
);

fn decode_head(provider: &ProviderId, raw: RawHead) -> Result<Head, CredentialLifecycleError> {
    if raw.0 != Value::Text(provider.as_str().to_owned()) {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let lifecycle = positive_integer(raw.1)?;
    let fence = positive_integer(raw.2)?;
    let readiness = positive_integer(raw.3)?;
    let next_version = positive_integer(raw.4)?;
    let active = decode_active(provider, raw.5, raw.6)?;
    let hard_fenced = match raw.7 {
        Value::Null => false,
        Value::Text(value) if value == "INVARIANT_FAILURE" => true,
        _ => return Err(CredentialLifecycleError::CorruptState),
    };
    let observed_at = nonnegative_integer(raw.8)?;
    Ok(Head {
        lifecycle,
        fence,
        readiness,
        next_version,
        active,
        hard_fenced,
        observed_at,
    })
}

fn decode_active(
    provider: &ProviderId,
    version: Value,
    digest: Value,
) -> Result<Option<CredentialVersionRef>, CredentialLifecycleError> {
    match (version, digest) {
        (Value::Null, Value::Null) => Ok(None),
        (Value::Integer(version), Value::Blob(digest)) => {
            let version = CredentialVersionRef::new(
                provider.clone(),
                u64::try_from(version).map_err(|_| CredentialLifecycleError::CorruptState)?,
            )
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
            if digest.as_slice() != version.ref_digest() {
                return Err(CredentialLifecycleError::CorruptState);
            }
            Ok(Some(version))
        }
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}

fn positive_integer(value: Value) -> Result<i64, CredentialLifecycleError> {
    match value {
        Value::Integer(value) if value > 0 => Ok(value),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}

fn nonnegative_integer(value: Value) -> Result<i64, CredentialLifecycleError> {
    match value {
        Value::Integer(value) if value >= 0 => Ok(value),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}

pub(super) fn ensure_head(
    transaction: &rusqlite::Transaction<'_>,
    provider: &ProviderId,
) -> Result<Head, CredentialLifecycleError> {
    transaction.execute(
        "INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES (?1, 1, 1, 1, 1) ON CONFLICT(provider_id) DO NOTHING",
        [provider.as_str()],
    ).map_err(map_sql)?;
    load_head(transaction, provider)?.ok_or(CredentialLifecycleError::CorruptState)
}
