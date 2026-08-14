use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;
use gocode_domain::id::{ProjectId, WorkspaceId};
use gocode_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use rusqlite::Row;

const MAX_REHYDRATED_VERSION: u64 = 1_000_000;

pub(super) fn project_from_row(row: &Row<'_>) -> Result<Project, rusqlite::Error> {
    let id: Vec<u8> = row.get(0)?;
    let name: String = row.get(1)?;
    let version: i64 = row.get(2)?;
    let archived: i64 = row.get(3)?;
    rehydrate_project(id, name, version, archived).map_err(codec_sql_error)
}

pub(super) fn workspace_from_row(row: &Row<'_>) -> Result<Workspace, rusqlite::Error> {
    let id: Vec<u8> = row.get(0)?;
    let project_id: Vec<u8> = row.get(1)?;
    let name: String = row.get(2)?;
    let version: i64 = row.get(3)?;
    let open: i64 = row.get(4)?;
    rehydrate_workspace(id, project_id, name, version, open).map_err(codec_sql_error)
}

fn rehydrate_project(
    id: Vec<u8>,
    name: String,
    version: i64,
    archived: i64,
) -> Result<Project, Error> {
    let id = ProjectId::from_bytes(id.try_into().map_err(|_| Error::InvariantViolation)?);
    let name = ProjectWorkspaceDisplayName::new(name).map_err(|_| Error::InvariantViolation)?;
    let version = u64::try_from(version).map_err(|_| Error::InvariantViolation)?;
    if version == 0 || version > MAX_REHYDRATED_VERSION || archived != i64::from(version % 2 == 0) {
        return Err(Error::InvariantViolation);
    }
    let mut project = Project::create(id, name);
    for _ in 1..version {
        if project.archived() {
            project.restore()
        } else {
            project.archive()
        }
        .map_err(|_| Error::InvariantViolation)?;
    }
    Ok(project)
}

fn rehydrate_workspace(
    id: Vec<u8>,
    project_id: Vec<u8>,
    name: String,
    version: i64,
    open: i64,
) -> Result<Workspace, Error> {
    let id = WorkspaceId::from_bytes(id.try_into().map_err(|_| Error::InvariantViolation)?);
    let project_id = ProjectId::from_bytes(
        project_id
            .try_into()
            .map_err(|_| Error::InvariantViolation)?,
    );
    let name = ProjectWorkspaceDisplayName::new(name).map_err(|_| Error::InvariantViolation)?;
    let version = u64::try_from(version).map_err(|_| Error::InvariantViolation)?;
    if version == 0
        || version > MAX_REHYDRATED_VERSION
        || !matches!(open, 0 | 1)
        || (open == 1 && version == 1)
    {
        return Err(Error::InvariantViolation);
    }
    let mut workspace = Workspace::create(id, project_id, name);
    if open == 1 {
        workspace.open().map_err(|_| Error::InvariantViolation)?;
    }
    for _ in (1 + u64::from(open == 1))..version {
        workspace
            .bind_root()
            .map_err(|_| Error::InvariantViolation)?;
    }
    Ok(workspace)
}

fn codec_sql_error(_: Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(RecordError))
}

#[derive(Debug)]
struct RecordError;

impl std::fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid Project/Workspace record")
    }
}

impl std::error::Error for RecordError {}
