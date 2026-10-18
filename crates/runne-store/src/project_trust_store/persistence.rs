//! Durable `ProjectTrustPersistence` implementation for the sidecar store.

use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
    TrustPersistenceError, TrustToken,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::ProjectTrustStore;
pub(super) use super::records::{insert_first_row, row_to_record, status_to_int, update_row};

impl ProjectTrustPersistence for ProjectTrustStore {
    fn acquire_control_lease(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<
        Box<dyn runne_application::project_trust::ProjectTrustControlLease>,
        TrustPersistenceError,
    > {
        super::control::acquire_control_lease(self, project)
    }

    fn has_explicit_record(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<bool, TrustPersistenceError> {
        self.with_connection(|connection| {
            let row: Option<i64> = connection
                .query_row(
                    "SELECT 1 FROM project_trust WHERE project_id = ?1",
                    params![project.as_bytes()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| TrustPersistenceError::Unavailable)?;
            Ok(row.is_some())
        })
    }

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
                None => Ok(ProjectTrustRecord::untrusted_default(self.instance_epoch)),
                Some((status, mask, revision)) => {
                    row_to_record(self.instance_epoch, status, mask, revision)
                        .ok_or(TrustPersistenceError::Unavailable)
                }
            }
        })
    }

    fn instance_epoch(&self) -> Result<u64, TrustPersistenceError> {
        self.with_connection(|_| Ok(self.instance_epoch))
    }

    fn acquire_effect_lease(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<
        Box<dyn runne_application::project_trust::ProjectTrustEffectLease>,
        TrustPersistenceError,
    > {
        Ok(Box::new(super::current_fence::acquire_current(
            self, project,
        )?))
    }

    fn commit(
        &self,
        project: ProjectTrustProjectId,
        status: ProjectTrustStatus,
        managed_deny_mask: u32,
        expected: TrustToken,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
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
        connection
            .verify_retained_identity()
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
        connection
            .verify_retained_identity()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        Ok(record)
    }
}
