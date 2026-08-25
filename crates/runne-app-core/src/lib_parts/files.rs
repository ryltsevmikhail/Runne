impl AppCore {
    /// Reads one bounded authenticated Workspace file page from the runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed runtime failure for invalid identity, unavailable
    /// runtime, incompatible capability, or malformed response.
    pub async fn list_workspace_files(
        &self,
        workspace_id: &str,
        path: &str,
        limit: u16,
    ) -> Result<CanonicalWorkspaceFilePage, AppCoreError> {
        let workspace_id =
            CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        let page = self
            .live_runtime_client()?
            .list_workspace_files(workspace_id, path.to_owned(), limit)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalWorkspaceFilePage {
            items: page
                .items()
                .iter()
                .map(CanonicalWorkspaceFileEntry::from)
                .collect(),
        })
    }

    /// Reads one bounded UTF-8 Workspace file through the runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed runtime failure for invalid identity, unavailable
    /// runtime, incompatible capability, or malformed response.
    pub async fn read_workspace_file(
        &self,
        workspace_id: &str,
        path: &str,
    ) -> Result<CanonicalWorkspaceFileContent, AppCoreError> {
        let workspace_id =
            CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        let content = self
            .live_runtime_client()?
            .read_workspace_file(workspace_id, path.to_owned())
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalWorkspaceFileContent {
            path: content.path().to_owned(),
            content: content.content().to_owned(),
            size_bytes: content.size_bytes(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceFilePage {
    pub items: Vec<CanonicalWorkspaceFileEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceFileEntry {
    pub path: String,
    pub kind: CanonicalWorkspaceFileKind,
    pub size_bytes: u64,
}

impl From<&WorkspaceFileEntryDto> for CanonicalWorkspaceFileEntry {
    fn from(value: &WorkspaceFileEntryDto) -> Self {
        Self {
            path: value.path().to_owned(),
            kind: CanonicalWorkspaceFileKind::from(value.kind()),
            size_bytes: value.size_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalWorkspaceFileKind {
    File,
    Directory,
}

impl From<WorkspaceFileKindDto> for CanonicalWorkspaceFileKind {
    fn from(value: WorkspaceFileKindDto) -> Self {
        match value {
            WorkspaceFileKindDto::File => Self::File,
            WorkspaceFileKindDto::Directory => Self::Directory,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkspaceFileContent {
    pub path: String,
    pub content: String,
    pub size_bytes: u64,
}
