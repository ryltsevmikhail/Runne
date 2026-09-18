//! Durable `ProjectTrustPersistence` implementation for the sidecar store.

use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
    TrustPersistenceError, TrustToken,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::ProjectTrustStore;

fn status_to_int(status: ProjectTrustStatus) -> i64 {
    match status {
        ProjectTrustStatus::Untrusted => 1,
        ProjectTrustStatus::Trusted => 2,
        ProjectTrustStatus::Managed => 3,
    }
}

fn status_from_int(value: i64) -> Option<ProjectTrustStatus> {
    match value {
        1 => Some(ProjectTrustStatus::Untrusted),
        2 => Some(ProjectTrustStatus::Trusted),
        3 => Some(ProjectTrustStatus::Managed),
        _ => None,
    }
}

fn row_to_record(
    instance_epoch: u64,
    status: i64,
    mask: i64,
    revision: i64,
) -> Option<ProjectTrustRecord> {
    Some(ProjectTrustRecord {
        status: status_from_int(status)?,
        instance_epoch,
        managed_deny_mask: u32::try_from(mask).ok()?,
        revision: u64::try_from(revision).ok()?,
    })
}

impl ProjectTrustPersistence for ProjectTrustStore {
    fn load(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        self.with_connection(|connection| {
            let row: Option<(i64, i64, i64)> = connection
                .query_row(
                    "SELECT status, managed_deny_mask, revision
                     FROM project_trust WHERE project_id = ?1",
                    params![project.as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| TrustPersistenceError::Unavailable)?;
            match row {
                // Absent projects read as the epoch-scoped untrusted default.
                None => Ok(ProjectTrustRecord::untrusted_default(self.instance_epoch)),
                Some((status, mask, revision)) => {
                    row_to_record(self.instance_epoch, status, mask, revision)
                        .ok_or(TrustPersistenceError::Unavailable)
                }
            }
        })
    }

    fn instance_epoch(&self) -> Result<u64, TrustPersistenceError> {
        Ok(self.instance_epoch)
    }

    fn commit(
        &self,
        project: ProjectTrustProjectId,
        status: ProjectTrustStatus,
        managed_deny_mask: u32,
        expected: TrustToken,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        // F1: a CAS token from a foreign epoch can never write here, so stale
        // grants cannot mutate a recreated sidecar regardless of revision.
        let instance_epoch = self.instance_epoch;
        if expected.instance_epoch != instance_epoch {
            return Err(TrustPersistenceError::ForeignEpoch {
                expected_epoch: expected.instance_epoch,
                current_epoch: instance_epoch,
            });
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM project_trust WHERE project_id = ?1",
                params![project.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        let record = match current {
            None => {
                if expected.revision != 0 {
                    return Err(TrustPersistenceError::Conflict {
                        expected: expected.revision,
                        current: 0,
                    });
                }
                insert_first_row(&transaction, project, status, managed_deny_mask)
                    .map_err(|_| TrustPersistenceError::Unavailable)?;
                ProjectTrustRecord {
                    status,
                    instance_epoch,
                    revision: 1,
                    managed_deny_mask,
                }
            }
            Some(current_revision) => {
                let current_revision = u64::try_from(current_revision)
                    .map_err(|_| TrustPersistenceError::Unavailable)?;
                if expected.revision != current_revision {
                    return Err(TrustPersistenceError::Conflict {
                        expected: expected.revision,
                        current: current_revision,
                    });
                }
                let next_revision = current_revision
                    .checked_add(1)
                    .ok_or(TrustPersistenceError::Unavailable)?;
                let changed = update_row(
                    &transaction,
                    project,
                    status,
                    managed_deny_mask,
                    current_revision,
                    next_revision,
                )
                .map_err(|_| TrustPersistenceError::Unavailable)?;
                if changed != 1 {
                    return Err(TrustPersistenceError::Conflict {
                        expected: expected.revision,
                        current: next_revision,
                    });
                }
                ProjectTrustRecord {
                    status,
                    instance_epoch,
                    revision: next_revision,
                    managed_deny_mask,
                }
            }
        };
        transaction
            .commit()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        Ok(record)
    }
}

fn insert_first_row(
    transaction: &rusqlite::Transaction<'_>,
    project: ProjectTrustProjectId,
    status: ProjectTrustStatus,
    managed_deny_mask: u32,
) -> rusqlite::Result<usize> {
    transaction.execute(
        "INSERT INTO project_trust
         (project_id, status, managed_deny_mask, revision, updated_at)
         VALUES (?1, ?2, ?3, 1, strftime('%s','now'))",
        params![
            project.as_bytes().as_slice(),
            status_to_int(status),
            i64::from(managed_deny_mask)
        ],
    )
}

fn update_row(
    transaction: &rusqlite::Transaction<'_>,
    project: ProjectTrustProjectId,
    status: ProjectTrustStatus,
    managed_deny_mask: u32,
    current_revision: u64,
    next_revision: u64,
) -> rusqlite::Result<usize> {
    transaction.execute(
        "UPDATE project_trust
         SET status = ?2, managed_deny_mask = ?3,
             revision = ?4, updated_at = strftime('%s','now')
         WHERE project_id = ?1 AND revision = ?5",
        params![
            project.as_bytes().as_slice(),
            status_to_int(status),
            i64::from(managed_deny_mask),
            next_revision,
            current_revision
        ],
    )
}
