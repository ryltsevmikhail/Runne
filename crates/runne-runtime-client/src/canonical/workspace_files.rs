/// Capability required before a client may issue Workspace file queries.
pub const WORKSPACE_FILES_CAPABILITY_V1: &str = "workspace.files.read.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceFileKindDto { File, Directory }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFileEntryDto {
    path: String,
    kind: WorkspaceFileKindDto,
    size_bytes: u64,
}
impl WorkspaceFileEntryDto {
    #[must_use]
    pub fn path(&self) -> &str { &self.path }
    #[must_use]
    pub const fn kind(&self) -> WorkspaceFileKindDto { self.kind }
    #[must_use]
    pub const fn size_bytes(&self) -> u64 { self.size_bytes }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFilePageDto { items: Vec<WorkspaceFileEntryDto> }
impl WorkspaceFilePageDto {
    #[must_use]
    pub fn items(&self) -> &[WorkspaceFileEntryDto] { &self.items }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFileContentDto { path: String, content: String, size_bytes: u64 }
impl WorkspaceFileContentDto {
    #[must_use]
    pub fn path(&self) -> &str { &self.path }
    #[must_use]
    pub fn content(&self) -> &str { &self.content }
    #[must_use]
    pub const fn size_bytes(&self) -> u64 { self.size_bytes }
}

impl AuthenticatedRuntimeClient {
    /// Reads one bounded, authenticated Workspace file page.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for invalid paths, transport errors, or malformed
    /// runtime responses.
    pub async fn list_workspace_files(
        &self,
        workspace_id: CanonicalId,
        path: impl Into<String>,
        limit: u16,
    ) -> Result<WorkspaceFilePageDto, RuntimeApiError> {
        require_capability(self, WORKSPACE_FILES_CAPABILITY_V1)?;
        let path = path.into();
        validate_request(workspace_id, &path, Some(limit), true)?;
        let response = self
            .authenticated_request(
                self.http_client()
                    .get(self.url(&format!("/v1/workspaces/{workspace_id}/files")))
                    .query(&[("path", path), ("limit", limit.to_string())]),
            )?
            .send()
            .await
            .map_err(map_transport)?;
        let wire: FilePageWire = read_success_json(response, &[200]).await?;
        let items = wire
            .items
            .into_iter()
            .map(WorkspaceFileEntryDto::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        (items.len() <= usize::from(limit)
            && items.windows(2).all(|pair| pair[0].path < pair[1].path))
            .then_some(WorkspaceFilePageDto { items })
            .ok_or_else(invalid_response)
    }

    /// Reads one bounded UTF-8 Workspace file.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for invalid paths, transport errors, or malformed
    /// runtime responses.
    pub async fn read_workspace_file(
        &self,
        workspace_id: CanonicalId,
        path: impl Into<String>,
    ) -> Result<WorkspaceFileContentDto, RuntimeApiError> {
        require_capability(self, WORKSPACE_FILES_CAPABILITY_V1)?;
        let path = path.into();
        validate_request(workspace_id, &path, None, false)?;
        let response = self
            .authenticated_request(
                self.http_client()
                    .get(self.url(&format!("/v1/workspaces/{workspace_id}/files/content")))
                    .query(&[("path", path.clone())]),
            )?
            .send()
            .await
            .map_err(map_transport)?;
        let content = WorkspaceFileContentDto::try_from(
            read_success_json::<FileContentWire>(response, &[200]).await?,
        )?;
        (content.path == path).then_some(content).ok_or_else(invalid_response)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FilePageWire { items: Vec<FileEntryWire> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileEntryWire { path: String, kind: FileKindWire, size_bytes: u64 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileContentWire { path: String, content: String, size_bytes: u64 }
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FileKindWire { File, Directory }

impl TryFrom<FileEntryWire> for WorkspaceFileEntryDto {
    type Error = RuntimeApiError;
    fn try_from(value: FileEntryWire) -> Result<Self, Self::Error> {
        runne_api::WorkspaceFileEntry::new(
            value.path.clone(),
            match value.kind { FileKindWire::File => runne_api::WorkspaceFileKind::File, FileKindWire::Directory => runne_api::WorkspaceFileKind::Directory },
            value.size_bytes,
        ).map_err(|_| invalid_response())?;
        Ok(Self { path: value.path, kind: match value.kind { FileKindWire::File => WorkspaceFileKindDto::File, FileKindWire::Directory => WorkspaceFileKindDto::Directory }, size_bytes: value.size_bytes })
    }
}
impl TryFrom<FileContentWire> for WorkspaceFileContentDto {
    type Error = RuntimeApiError;
    fn try_from(value: FileContentWire) -> Result<Self, Self::Error> {
        runne_api::WorkspaceFileContent::new(value.path.clone(), value.content.clone(), value.size_bytes).map_err(|_| invalid_response())?;
        Ok(Self { path: value.path, content: value.content, size_bytes: value.size_bytes })
    }
}

fn validate_request(id: CanonicalId, path: &str, limit: Option<u16>, allow_empty: bool) -> Result<(), RuntimeApiError> {
    let workspace_id = id.to_string().parse().map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
    if let Some(limit) = limit { runne_api::WorkspaceFileListRequest::new(workspace_id, path, limit).map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?; }
    else { runne_api::WorkspaceFileReadRequest::new(workspace_id, path).map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?; }
    if !allow_empty && path.is_empty() { return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest)); }
    Ok(())
}

fn require_capability(client: &AuthenticatedRuntimeClient, capability: &str) -> Result<(), RuntimeApiError> {
    client.session_info().capabilities.iter().any(|value| value == capability)
        .then_some(())
        .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::Incompatible))
}
