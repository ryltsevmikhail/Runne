//! Trust-control writer lease and same-connection decision CAS.

use runne_application::project_trust::{
    ProjectTrustControlLease, ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
    TrustPersistenceError, TrustToken,
};
use rusqlite::{OptionalExtension, params};

use super::{
    ProjectTrustStore,
    persistence::{row_to_record, status_to_int},
};
use crate::schema;

pub(super) fn acquire_control_lease(
    store: &ProjectTrustStore,
    project: ProjectTrustProjectId,
) -> Result<Box<dyn ProjectTrustControlLease>, TrustPersistenceError> {
    let (mut connection, epoch) =
        schema::reopen_managed_project_trust_sidecar(&store.sidecar_path, store.authority_id)
            .map_err(|_| TrustPersistenceError::Unavailable)?;
    if epoch != store.instance_epoch {
        return Err(TrustPersistenceError::Unavailable);
    }
    let original = store
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
    let (stored_epoch, authority): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT instance_epoch, authority_id FROM project_trust_schema WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    if u64::try_from(stored_epoch).ok() != Some(epoch) || authority.as_slice() != store.authority_id
    {
        return Err(TrustPersistenceError::Unavailable);
    }
    let row: Option<(i64, i64, i64)> = connection
        .query_row(
            "SELECT status, managed_deny_mask, revision FROM project_trust WHERE project_id = ?1",
            params![project.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    let record = match row {
        None => ProjectTrustRecord::untrusted_default(epoch),
        Some((status, mask, revision)) => row_to_record(epoch, status, mask, revision)
            .ok_or(TrustPersistenceError::Unavailable)?,
    };
    Ok(Box::new(ControlLease {
        connection: Some(connection),
        project,
        record,
    }))
}

struct ControlLease {
    connection: Option<crate::schema::ManagedConnection>,
    project: ProjectTrustProjectId,
    record: ProjectTrustRecord,
}

impl ProjectTrustControlLease for ControlLease {
    fn record(&self) -> ProjectTrustRecord {
        self.record
    }

    fn decide(
        &mut self,
        trusted: bool,
        expected: TrustToken,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        if expected.instance_epoch != self.record.instance_epoch {
            return Err(TrustPersistenceError::ForeignEpoch {
                expected_epoch: expected.instance_epoch,
                current_epoch: self.record.instance_epoch,
            });
        }
        if expected.revision != self.record.revision {
            return Err(TrustPersistenceError::Conflict {
                expected: expected.revision,
                current: self.record.revision,
            });
        }
        if self.record.status == ProjectTrustStatus::Managed || self.record.managed_deny_mask != 0 {
            return Err(TrustPersistenceError::Unavailable);
        }
        let next = self
            .record
            .revision
            .checked_add(1)
            .ok_or(TrustPersistenceError::Unavailable)?;
        let status = if trusted {
            ProjectTrustStatus::Trusted
        } else {
            ProjectTrustStatus::Untrusted
        };
        let connection = self
            .connection
            .as_mut()
            .ok_or(TrustPersistenceError::Unavailable)?;
        connection
            .verify_retained_identity()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        let changed = connection
            .with_connection_mut(|raw| {
                if self.record.revision == 0 {
                    raw.execute(
                        "INSERT INTO project_trust (project_id, status, managed_deny_mask, revision, updated_at) VALUES (?1, ?2, 0, ?3, strftime('%s','now'))",
                        params![self.project.as_bytes().as_slice(), status_to_int(status), next],
                    )
                } else {
                    raw.execute(
                        "UPDATE project_trust SET status = ?2, revision = ?3, updated_at = strftime('%s','now') WHERE project_id = ?1 AND revision = ?4 AND status != 3 AND managed_deny_mask = 0",
                        params![self.project.as_bytes().as_slice(), status_to_int(status), next, self.record.revision],
                    )
                }
            })
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        if changed != 1 {
            return Err(TrustPersistenceError::Conflict {
                expected: expected.revision,
                current: self.record.revision,
            });
        }
        connection
            .verify_retained_identity()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        connection
            .with_connection_mut(|raw| raw.execute_batch("COMMIT"))
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        connection
            .verify_retained_identity()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        self.connection.take();
        self.record = ProjectTrustRecord {
            status,
            revision: next,
            managed_deny_mask: 0,
            ..self.record
        };
        Ok(self.record)
    }
}

impl Drop for ControlLease {
    fn drop(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            let _ = connection.with_connection_mut(|raw| raw.execute_batch("ROLLBACK"));
        }
    }
}
