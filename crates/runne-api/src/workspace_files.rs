//! Canonical, bounded Workspace file query contracts.

use crate::{ApiPrincipalId, WorkspaceId};
use std::future::Future;

pub const MAX_WORKSPACE_FILE_PAGE_SIZE: u16 = 200;
pub const MAX_WORKSPACE_FILE_PATH_BYTES: usize = 4096;
pub const MAX_WORKSPACE_FILE_CONTENT_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceFileKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFileEntry {
    relative_path: String,
    kind: WorkspaceFileKind,
    size_bytes: u64,
}

impl WorkspaceFileEntry {
    pub fn new(
        relative_path: impl Into<String>,
        kind: WorkspaceFileKind,
        size_bytes: u64,
    ) -> Result<Self, WorkspaceFileHostError> {
        let relative_path = validate_relative_path(relative_path.into(), false)?;
        Ok(Self {
            relative_path,
            kind,
            size_bytes,
        })
    }
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    #[must_use]
    pub const fn kind(&self) -> WorkspaceFileKind {
        self.kind
    }
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFilePage {
    items: Vec<WorkspaceFileEntry>,
}

impl WorkspaceFilePage {
    pub fn new(limit: u16, items: Vec<WorkspaceFileEntry>) -> Result<Self, WorkspaceFileHostError> {
        if limit == 0 || limit > MAX_WORKSPACE_FILE_PAGE_SIZE || items.len() > usize::from(limit) {
            return Err(WorkspaceFileHostError::InvariantViolation);
        }
        let unique = items
            .windows(2)
            .all(|pair| pair[0].relative_path < pair[1].relative_path);
        unique
            .then_some(Self { items })
            .ok_or(WorkspaceFileHostError::InvariantViolation)
    }
    #[must_use]
    pub fn items(&self) -> &[WorkspaceFileEntry] {
        &self.items
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFileContent {
    relative_path: String,
    content: String,
    size_bytes: u64,
}

impl WorkspaceFileContent {
    pub fn new(
        relative_path: impl Into<String>,
        content: String,
        size_bytes: u64,
    ) -> Result<Self, WorkspaceFileHostError> {
        let relative_path = validate_relative_path(relative_path.into(), false)?;
        if content.len() > MAX_WORKSPACE_FILE_CONTENT_BYTES || size_bytes != content.len() as u64 {
            return Err(WorkspaceFileHostError::SizeLimit);
        }
        Ok(Self {
            relative_path,
            content,
            size_bytes,
        })
    }
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFileListRequest {
    workspace_id: WorkspaceId,
    relative_path: String,
    limit: u16,
}

impl WorkspaceFileListRequest {
    pub fn new(
        workspace_id: WorkspaceId,
        relative_path: impl Into<String>,
        limit: u16,
    ) -> Result<Self, WorkspaceFileHostError> {
        if limit == 0 || limit > MAX_WORKSPACE_FILE_PAGE_SIZE {
            return Err(WorkspaceFileHostError::InvalidLimit);
        }
        Ok(Self {
            workspace_id,
            relative_path: validate_relative_path(relative_path.into(), true)?,
            limit,
        })
    }
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFileReadRequest {
    workspace_id: WorkspaceId,
    relative_path: String,
}

impl WorkspaceFileReadRequest {
    pub fn new(
        workspace_id: WorkspaceId,
        relative_path: impl Into<String>,
    ) -> Result<Self, WorkspaceFileHostError> {
        Ok(Self {
            workspace_id,
            relative_path: validate_relative_path(relative_path.into(), false)?,
        })
    }
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceFileQueryContext {
    pub principal: ApiPrincipalId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceFileHostError {
    InvalidPath,
    InvalidLimit,
    NotFound,
    Forbidden,
    Conflict,
    SizeLimit,
    BinaryContent,
    Backpressure,
    Unavailable,
    InvariantViolation,
}

pub trait WorkspaceFileHostPort: Send + Sync {
    fn list_files(
        &self,
        context: WorkspaceFileQueryContext,
        request: WorkspaceFileListRequest,
    ) -> impl Future<Output = Result<WorkspaceFilePage, WorkspaceFileHostError>> + Send;
    fn read_file(
        &self,
        context: WorkspaceFileQueryContext,
        request: WorkspaceFileReadRequest,
    ) -> impl Future<Output = Result<WorkspaceFileContent, WorkspaceFileHostError>> + Send;
}

fn validate_relative_path(
    value: String,
    allow_empty: bool,
) -> Result<String, WorkspaceFileHostError> {
    if value.len() > MAX_WORKSPACE_FILE_PATH_BYTES
        || (!allow_empty && value.is_empty())
        || value.starts_with('/')
        || value.contains('\\')
        || value.bytes().any(|byte| byte == 0 || byte < 0x20)
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(WorkspaceFileHostError::InvalidPath);
    }
    Ok(value)
}
