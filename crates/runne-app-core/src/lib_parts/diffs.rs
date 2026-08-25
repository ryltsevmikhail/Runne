impl AppCore {
    /// Lists the bounded authenticated Workspace changes from the runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed runtime failure for invalid identity, unavailable
    /// runtime, incompatible capability, or malformed response.
    pub async fn list_workspace_changes(
        &self,
        workspace_id: &str,
        limit: u16,
    ) -> Result<CanonicalWorkspaceChangeSet, AppCoreError> {
        let workspace_id = CanonicalId::parse(workspace_id)
            .map_err(|_| AppCoreError::ProjectUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        let changes = self
            .live_runtime_client()?
            .list_workspace_changes(workspace_id, limit)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalWorkspaceChangeSet {
            items: changes
                .entries()
                .iter()
                .map(CanonicalWorkspaceChangeEntry::from)
                .collect(),
        })
    }

    /// Reads one bounded structured Workspace diff from the runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed runtime failure for invalid identity, unavailable
    /// runtime, incompatible capability, or malformed response.
    pub async fn read_workspace_diff(
        &self,
        workspace_id: &str,
        path: &str,
    ) -> Result<CanonicalWorkspaceDiff, AppCoreError> {
        let workspace_id = CanonicalId::parse(workspace_id)
            .map_err(|_| AppCoreError::ProjectUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        let diff = self
            .live_runtime_client()?
            .read_workspace_diff(workspace_id, path.to_owned())
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalWorkspaceDiff::from(&diff))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceChangeSet {
    pub items: Vec<CanonicalWorkspaceChangeEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceChangeEntry {
    pub path: String,
    pub kind: CanonicalWorkspaceChangeKind,
    pub additions: u32,
    pub deletions: u32,
}

impl From<&WorkspaceChangeEntryDto> for CanonicalWorkspaceChangeEntry {
    fn from(value: &WorkspaceChangeEntryDto) -> Self {
        Self {
            path: value.path().to_owned(),
            kind: CanonicalWorkspaceChangeKind::from(value.kind()),
            additions: value.additions(),
            deletions: value.deletions(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalWorkspaceChangeKind {
    Added,
    Modified,
    Deleted,
}

impl From<WorkspaceChangeKindDto> for CanonicalWorkspaceChangeKind {
    fn from(value: WorkspaceChangeKindDto) -> Self {
        match value {
            WorkspaceChangeKindDto::Added => Self::Added,
            WorkspaceChangeKindDto::Modified => Self::Modified,
            WorkspaceChangeKindDto::Deleted => Self::Deleted,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceDiff {
    pub path: String,
    pub kind: CanonicalWorkspaceChangeKind,
    pub hunks: Vec<CanonicalWorkspaceDiffHunk>,
    pub truncated: bool,
}

impl From<&WorkspaceDiffDto> for CanonicalWorkspaceDiff {
    fn from(value: &WorkspaceDiffDto) -> Self {
        Self {
            path: value.path().to_owned(),
            kind: CanonicalWorkspaceChangeKind::from(value.kind()),
            hunks: value
                .hunks()
                .iter()
                .map(CanonicalWorkspaceDiffHunk::from)
                .collect(),
            truncated: value.truncated(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceDiffHunk {
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    pub lines: Vec<CanonicalWorkspaceDiffLine>,
}

impl From<&WorkspaceDiffHunkDto> for CanonicalWorkspaceDiffHunk {
    fn from(value: &WorkspaceDiffHunkDto) -> Self {
        Self {
            old_start: value.old_start(),
            old_lines: value.old_lines(),
            new_start: value.new_start(),
            new_lines: value.new_lines(),
            lines: value
                .lines()
                .iter()
                .map(CanonicalWorkspaceDiffLine::from)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceDiffLine {
    pub kind: CanonicalWorkspaceDiffLineKind,
    pub text: String,
}

impl From<&WorkspaceDiffLineDto> for CanonicalWorkspaceDiffLine {
    fn from(value: &WorkspaceDiffLineDto) -> Self {
        Self {
            kind: CanonicalWorkspaceDiffLineKind::from(value.kind()),
            text: value.text().to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalWorkspaceDiffLineKind {
    Context,
    Added,
    Removed,
}

impl From<WorkspaceDiffLineKindDto> for CanonicalWorkspaceDiffLineKind {
    fn from(value: WorkspaceDiffLineKindDto) -> Self {
        match value {
            WorkspaceDiffLineKindDto::Context => Self::Context,
            WorkspaceDiffLineKindDto::Added => Self::Added,
            WorkspaceDiffLineKindDto::Removed => Self::Removed,
        }
    }
}
