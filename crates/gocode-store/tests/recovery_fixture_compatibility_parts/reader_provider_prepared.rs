use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::{FixtureValidationError, hex, readonly};

pub(crate) fn validate_provider_prepared(
    path: &Path,
) -> Result<Vec<BTreeMap<String, String>>, FixtureValidationError> {
    let connection = readonly(path)?;
    let mut statement = connection
        .prepare(
            "SELECT call_id, prepared_digest, render_digest, profile_digest, record_digest
             FROM provider_prepared_requests ORDER BY call_id",
        )
        .map_err(|_| FixtureValidationError::Corrupt)?;
    statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .map_err(|_| FixtureValidationError::Corrupt)?
        .map(|row| {
            let (call_id, prepared, render, profile, record) =
                row.map_err(|_| FixtureValidationError::Corrupt)?;
            if call_id.len() != 16
                || prepared.len() != 32
                || render.len() != 32
                || profile.len() != 32
                || record.len() != 32
            {
                return Err(FixtureValidationError::Corrupt);
            }
            let mut hasher = Sha256::new();
            hasher.update(b"GOCODE_PROVIDER_PREPARED_V1\0");
            hasher.update(&call_id);
            hasher.update(&prepared);
            hasher.update(&render);
            hasher.update(&profile);
            if hasher.finalize().as_slice() != record {
                return Err(FixtureValidationError::Corrupt);
            }
            Ok(BTreeMap::from([
                ("call_id".into(), hex(&call_id)),
                ("prepared_digest".into(), hex(&prepared)),
                ("render_digest".into(), hex(&render)),
                ("profile_digest".into(), hex(&profile)),
                ("record_digest".into(), hex(&record)),
            ]))
        })
        .collect()
}
