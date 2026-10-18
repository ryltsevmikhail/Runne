use runne_application::project_trust::{
    ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
};
use rusqlite::params;

pub(super) fn status_to_int(status: ProjectTrustStatus) -> i64 {
    match status {
        ProjectTrustStatus::Untrusted => 1,
        ProjectTrustStatus::Trusted => 2,
        ProjectTrustStatus::Managed => 3,
    }
}

pub(super) fn status_from_int(value: i64) -> Option<ProjectTrustStatus> {
    match value {
        1 => Some(ProjectTrustStatus::Untrusted),
        2 => Some(ProjectTrustStatus::Trusted),
        3 => Some(ProjectTrustStatus::Managed),
        _ => None,
    }
}

pub(super) fn row_to_record(
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

pub(super) fn insert_first_row(
    transaction: &rusqlite::Transaction<'_>,
    project: ProjectTrustProjectId,
    status: ProjectTrustStatus,
    managed_deny_mask: u32,
) -> rusqlite::Result<usize> {
    let inserted = transaction.execute(
        "INSERT INTO project_trust
         (project_id, status, managed_deny_mask, revision, updated_at)
         VALUES (?1, ?2, ?3, 1, strftime('%s','now'))",
        params![
            project.as_bytes().as_slice(),
            status_to_int(status),
            i64::from(managed_deny_mask)
        ],
    )?;
    if inserted == 1 {
        super::effects::ensure_default_policy(transaction, project)?;
    }
    Ok(inserted)
}

pub(super) fn update_row(
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
