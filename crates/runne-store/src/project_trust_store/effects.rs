use runne_application::project_trust::{
    ManagedEffectDecision, ManagedEffectPolicyV1, ProjectTrustEffectLease,
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, ProjectTrustRecord,
    TrustPersistenceError,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::schema::ManagedConnection;

pub(super) struct StoreProjectTrustEffectLease {
    pub(super) connection: Option<ManagedConnection>,
    pub(super) snapshot: ProjectTrustEffectPolicySnapshot,
}

impl ProjectTrustEffectLease for StoreProjectTrustEffectLease {
    fn record(&self) -> ProjectTrustRecord {
        self.snapshot.record
    }

    fn snapshot(&self) -> Result<ProjectTrustEffectPolicySnapshot, TrustPersistenceError> {
        Ok(self.snapshot)
    }
}

impl Drop for StoreProjectTrustEffectLease {
    fn drop(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            let _ = connection.with_connection_mut(|raw| raw.execute_batch("ROLLBACK"));
        }
    }
}

pub(super) fn load_snapshot(
    connection: &Connection,
    project: ProjectTrustProjectId,
    record: ProjectTrustRecord,
    has_record: bool,
) -> Result<ProjectTrustEffectPolicySnapshot, TrustPersistenceError> {
    let row: Option<(i64, i64, i64, i64, i64, i64, i64)> = connection
        .query_row(
            "SELECT policy_version, fs_read, fs_create, fs_write, fs_delete,
                    process_start, network_use
             FROM managed_effect_policies WHERE project_id = ?1",
            params![project.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| TrustPersistenceError::Unavailable)?;
    let policy = match row {
        Some(values) => decode_policy(values).ok_or(TrustPersistenceError::Unavailable)?,
        None if !has_record => ManagedEffectPolicyV1::all_allow(),
        None => return Err(TrustPersistenceError::Unavailable),
    };
    let snapshot = ProjectTrustEffectPolicySnapshot { record, policy };
    if snapshot.is_valid() {
        Ok(snapshot)
    } else {
        Err(TrustPersistenceError::Unavailable)
    }
}

pub(super) fn ensure_default_policy(
    transaction: &rusqlite::Transaction<'_>,
    project: ProjectTrustProjectId,
) -> rusqlite::Result<usize> {
    transaction.execute(
        "INSERT OR IGNORE INTO managed_effect_policies
         (project_id, policy_version, fs_read, fs_create, fs_write, fs_delete,
          process_start, network_use)
         VALUES (?1, 1, 0, 0, 0, 0, 0, 0)",
        params![project.as_bytes().as_slice()],
    )
}

fn decode_policy(row: (i64, i64, i64, i64, i64, i64, i64)) -> Option<ManagedEffectPolicyV1> {
    let version = u32::try_from(row.0).ok()?;
    let values = [row.1, row.2, row.3, row.4, row.5, row.6];
    let decisions = values.map(|value| {
        u8::try_from(value)
            .ok()
            .and_then(ManagedEffectDecision::from_code)
    });
    let decisions = [
        decisions[0]?,
        decisions[1]?,
        decisions[2]?,
        decisions[3]?,
        decisions[4]?,
        decisions[5]?,
    ];
    let policy = ManagedEffectPolicyV1::new(version, decisions);
    policy.is_valid().then_some(policy)
}
