/// Capability required before a client may issue Workspace change queries.
pub const WORKSPACE_DIFFS_CAPABILITY_V1: &str = "workspace.changes.read.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceChangeKindDto {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceChangeEntryDto {
    path: String,
    kind: WorkspaceChangeKindDto,
    additions: u32,
    deletions: u32,
}

impl WorkspaceChangeEntryDto {
    #[must_use]
    pub fn path(&self) -> &str { &self.path }
    #[must_use]
    pub const fn kind(&self) -> WorkspaceChangeKindDto { self.kind }
    #[must_use]
    pub const fn additions(&self) -> u32 { self.additions }
    #[must_use]
    pub const fn deletions(&self) -> u32 { self.deletions }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceChangeSetDto { entries: Vec<WorkspaceChangeEntryDto> }
impl WorkspaceChangeSetDto {
    #[must_use]
    pub fn entries(&self) -> &[WorkspaceChangeEntryDto] { &self.entries }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceDiffLineKindDto { Context, Added, Removed }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceDiffLineDto {
    kind: WorkspaceDiffLineKindDto,
    text: String,
}
impl WorkspaceDiffLineDto {
    #[must_use]
    pub const fn kind(&self) -> WorkspaceDiffLineKindDto { self.kind }
    #[must_use]
    pub fn text(&self) -> &str { &self.text }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceDiffHunkDto {
    old_start: u32,
    old_lines: u32,
    new_start: u32,
    new_lines: u32,
    lines: Vec<WorkspaceDiffLineDto>,
}
impl WorkspaceDiffHunkDto {
    #[must_use]
    pub const fn old_start(&self) -> u32 { self.old_start }
    #[must_use]
    pub const fn old_lines(&self) -> u32 { self.old_lines }
    #[must_use]
    pub const fn new_start(&self) -> u32 { self.new_start }
    #[must_use]
    pub const fn new_lines(&self) -> u32 { self.new_lines }
    #[must_use]
    pub fn lines(&self) -> &[WorkspaceDiffLineDto] { &self.lines }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceDiffDto {
    path: String,
    kind: WorkspaceChangeKindDto,
    hunks: Vec<WorkspaceDiffHunkDto>,
    truncated: bool,
}
impl WorkspaceDiffDto {
    #[must_use]
    pub fn path(&self) -> &str { &self.path }
    #[must_use]
    pub const fn kind(&self) -> WorkspaceChangeKindDto { self.kind }
    #[must_use]
    pub fn hunks(&self) -> &[WorkspaceDiffHunkDto] { &self.hunks }
    #[must_use]
    pub const fn truncated(&self) -> bool { self.truncated }
}

impl AuthenticatedRuntimeClient {
    /// Lists the bounded changes visible for one workspace.
    ///
    /// # Errors
    ///
    /// Returns an error when the session lacks the capability, the request is
    /// invalid, transport fails, or the runtime sends an invalid response.
    pub async fn list_workspace_changes(
        &self,
        workspace_id: CanonicalId,
        limit: u16,
    ) -> Result<WorkspaceChangeSetDto, RuntimeApiError> {
        require_capability(self, WORKSPACE_DIFFS_CAPABILITY_V1)?;
        let runtime_id = workspace_id.to_string().parse().map_err(|_| invalid_request())?;
        let request = runne_api::WorkspaceChangeListRequest::new(runtime_id, limit)
            .map_err(|_| invalid_request())?;
        let response = self
            .authenticated_request(
                self.http_client()
                    .get(self.url(&format!("/v1/workspaces/{workspace_id}/changes")))
                    .query(&[("limit", request.limit().to_string())]),
            )?
            .send()
            .await
            .map_err(map_transport)?;
        let wire: ChangeSetWire = read_success_json(response, &[200]).await?;
        let entries = wire
            .items
            .into_iter()
            .map(WorkspaceChangeEntryDto::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        (entries.len() <= usize::from(limit)
            && entries.windows(2).all(|pair| pair[0].path < pair[1].path))
            .then_some(WorkspaceChangeSetDto { entries })
            .ok_or_else(invalid_response)
    }

    /// Reads one bounded structured diff visible for one workspace path.
    ///
    /// # Errors
    ///
    /// Returns an error when the session lacks the capability, the path is
    /// invalid, transport fails, or the runtime sends an invalid response.
    pub async fn read_workspace_diff(
        &self,
        workspace_id: CanonicalId,
        path: impl Into<String>,
    ) -> Result<WorkspaceDiffDto, RuntimeApiError> {
        require_capability(self, WORKSPACE_DIFFS_CAPABILITY_V1)?;
        let path = path.into();
        let runtime_id = workspace_id.to_string().parse().map_err(|_| invalid_request())?;
        runne_api::WorkspaceDiffReadRequest::new(runtime_id, path.clone()).map_err(|_| invalid_request())?;
        let response = self
            .authenticated_request(
                self.http_client()
                    .get(self.url(&format!("/v1/workspaces/{workspace_id}/diff")))
                    .query(&[("path", path.clone())]),
            )?
            .send()
            .await
            .map_err(map_transport)?;
        let diff = WorkspaceDiffDto::try_from(read_success_json::<DiffWire>(response, &[200]).await?)?;
        (diff.path == path).then_some(diff).ok_or_else(invalid_response)
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangeSetWire { items: Vec<ChangeEntryWire> }
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangeEntryWire { path: String, kind: ChangeKindWire, additions: u32, deletions: u32 }
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiffWire { path: String, kind: ChangeKindWire, hunks: Vec<HunkWire>, truncated: bool }
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HunkWire { old_start: u32, old_lines: u32, new_start: u32, new_lines: u32, lines: Vec<LineWire> }
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LineWire { kind: LineKindWire, text: String }
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChangeKindWire { Added, Modified, Deleted }
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum LineKindWire { Context, Added, Removed }

impl TryFrom<ChangeEntryWire> for WorkspaceChangeEntryDto {
    type Error = RuntimeApiError;
    fn try_from(value: ChangeEntryWire) -> Result<Self, Self::Error> {
        runne_api::WorkspaceChangeEntry::new(value.path.clone(), change_kind(value.kind), value.additions, value.deletions).map_err(|_| invalid_response())?;
        Ok(Self { path: value.path, kind: change_kind_dto(value.kind), additions: value.additions, deletions: value.deletions })
    }
}

impl TryFrom<DiffWire> for WorkspaceDiffDto {
    type Error = RuntimeApiError;
    fn try_from(value: DiffWire) -> Result<Self, Self::Error> {
        let pairs = value.hunks.into_iter().map(hunk).collect::<Result<Vec<_>, _>>()?;
        let api_hunks = pairs.iter().map(|pair| pair.0.clone()).collect();
        let hunks = pairs.into_iter().map(|pair| pair.1).collect();
        runne_api::WorkspaceDiff::new(value.path.clone(), change_kind(value.kind), api_hunks, value.truncated).map_err(|_| invalid_response())?;
        Ok(Self { path: value.path, kind: change_kind_dto(value.kind), hunks, truncated: value.truncated })
    }
}

fn hunk(value: HunkWire) -> Result<(runne_api::WorkspaceDiffHunk, WorkspaceDiffHunkDto), RuntimeApiError> {
    let mut api_lines = Vec::with_capacity(value.lines.len());
    let mut lines = Vec::with_capacity(value.lines.len());
    for line in value.lines {
        api_lines.push(runne_api::WorkspaceDiffLine::new(line_kind(line.kind), line.text.clone()).map_err(|_| invalid_response())?);
        lines.push(WorkspaceDiffLineDto { kind: line_kind_dto(line.kind), text: line.text });
    }
    let api_hunk = runne_api::WorkspaceDiffHunk::new(value.old_start, value.old_lines, value.new_start, value.new_lines, api_lines).map_err(|_| invalid_response())?;
    Ok((api_hunk, WorkspaceDiffHunkDto { old_start: value.old_start, old_lines: value.old_lines, new_start: value.new_start, new_lines: value.new_lines, lines }))
}

const fn change_kind(value: ChangeKindWire) -> runne_api::WorkspaceChangeKind {
    match value {
        ChangeKindWire::Added => runne_api::WorkspaceChangeKind::Added,
        ChangeKindWire::Modified => runne_api::WorkspaceChangeKind::Modified,
        ChangeKindWire::Deleted => runne_api::WorkspaceChangeKind::Deleted,
    }
}

const fn change_kind_dto(value: ChangeKindWire) -> WorkspaceChangeKindDto {
    match value {
        ChangeKindWire::Added => WorkspaceChangeKindDto::Added,
        ChangeKindWire::Modified => WorkspaceChangeKindDto::Modified,
        ChangeKindWire::Deleted => WorkspaceChangeKindDto::Deleted,
    }
}

const fn line_kind(value: LineKindWire) -> runne_api::WorkspaceDiffLineKind {
    match value {
        LineKindWire::Context => runne_api::WorkspaceDiffLineKind::Context,
        LineKindWire::Added => runne_api::WorkspaceDiffLineKind::Added,
        LineKindWire::Removed => runne_api::WorkspaceDiffLineKind::Removed,
    }
}

const fn line_kind_dto(value: LineKindWire) -> WorkspaceDiffLineKindDto {
    match value {
        LineKindWire::Context => WorkspaceDiffLineKindDto::Context,
        LineKindWire::Added => WorkspaceDiffLineKindDto::Added,
        LineKindWire::Removed => WorkspaceDiffLineKindDto::Removed,
    }
}
