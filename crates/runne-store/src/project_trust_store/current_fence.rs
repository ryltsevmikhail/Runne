use runne_application::project_trust::{
    ProjectTrustProjectId, ProjectTrustRecord, TrustPersistenceError,
};
use rusqlite::{OptionalExtension, params};

use super::{
    ProjectTrustStore,
    effects::{self, StoreProjectTrustEffectLease},
    persistence::row_to_record,
};

pub(super) fn acquire_current(
    owner: &ProjectTrustStore,
    project: ProjectTrustProjectId,
) -> Result<StoreProjectTrustEffectLease, TrustPersistenceError> {
    let (mut connection, epoch) = crate::schema::reopen_managed_project_trust_sidecar(
        &owner.sidecar_path,
        owner.authority_id,
    )
    .map_err(|_| TrustPersistenceError::Unavailable)?;
    if epoch != owner.instance_epoch {
        return Err(TrustPersistenceError::Unavailable);
    }
    let original = owner
        .connection
        .lock()
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    if !connection
        .same_database_identity(&original)
        .map_err(|_| TrustPersistenceError::Unavailable)?
    {
        return Err(TrustPersistenceError::Unavailable);
    }
    drop(original);
    connection
        .with_connection_mut(|raw| raw.execute_batch("BEGIN IMMEDIATE"))
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    connection
        .verify_retained_identity()
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    let (current_epoch, authority): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT instance_epoch, authority_id FROM project_trust_schema WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    if u64::try_from(current_epoch).ok() != Some(owner.instance_epoch)
        || authority.as_slice() != owner.authority_id
    {
        return Err(TrustPersistenceError::Unavailable);
    }
    let row: Option<(i64, i64, i64)> = connection
        .query_row(
            "SELECT status, managed_deny_mask, revision
             FROM project_trust WHERE project_id = ?1",
            params![project.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    let has_record = row.is_some();
    let record = match row {
        None => ProjectTrustRecord::untrusted_default(owner.instance_epoch),
        Some((status, mask, revision)) => {
            row_to_record(owner.instance_epoch, status, mask, revision)
                .ok_or(TrustPersistenceError::Unavailable)?
        }
    };
    let snapshot = effects::load_snapshot(&connection, project, record, has_record)?;
    connection
        .verify_retained_identity()
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    Ok(StoreProjectTrustEffectLease {
        connection: Some(connection),
        snapshot,
    })
}
