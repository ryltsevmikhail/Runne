use super::super::{CanonicalId, CommandIdentity, RuntimeApiError, RuntimeApiErrorKind};
use gocode_api::{
    ProjectWorkspaceDisplayNameInput, ProtectedRootBindTransport, ProtectedRootHandleAdmission,
};

/// Immutable Project snapshot returned by the authoritative runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectSnapshotDto {
    pub(super) id: CanonicalId,
    pub(super) name: String,
    pub(super) version: u64,
    pub(super) archived: bool,
}
impl ProjectSnapshotDto {
    pub const fn id(&self) -> CanonicalId {
        self.id
    }
    pub fn display_name(&self) -> &str {
        &self.name
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn archived(&self) -> bool {
        self.archived
    }
}

/// Immutable Workspace snapshot returned by the authoritative runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceSnapshotDto {
    pub(super) id: CanonicalId,
    pub(super) project_id: CanonicalId,
    pub(super) name: String,
    pub(super) version: u64,
    pub(super) open: bool,
}
impl WorkspaceSnapshotDto {
    pub const fn id(&self) -> CanonicalId {
        self.id
    }
    pub const fn project_id(&self) -> CanonicalId {
        self.project_id
    }
    pub fn display_name(&self) -> &str {
        &self.name
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn is_open(&self) -> bool {
        self.open
    }
}

/// Immutable acknowledgement of a versioned Project mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectCommandAcknowledgement {
    pub(super) id: CanonicalId,
    pub(super) version: u64,
}
impl ProjectCommandAcknowledgement {
    pub(crate) const fn observed(id: CanonicalId, version: u64) -> Self {
        Self { id, version }
    }
    pub const fn project_id(&self) -> CanonicalId {
        self.id
    }
    pub const fn new_version(&self) -> u64 {
        self.version
    }
}

/// Immutable acknowledgement of a versioned Workspace mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceCommandAcknowledgement {
    pub(super) id: CanonicalId,
    pub(super) version: u64,
}
impl WorkspaceCommandAcknowledgement {
    pub(crate) const fn observed(id: CanonicalId, version: u64) -> Self {
        Self { id, version }
    }
    pub const fn workspace_id(&self) -> CanonicalId {
        self.id
    }
    pub const fn new_version(&self) -> u64 {
        self.version
    }
}

/// Principal-bound opaque Project continuation token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectPageCursor(pub(super) String);
impl ProjectPageCursor {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Principal- and Project-bound opaque Workspace continuation token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspacePageCursor(pub(super) String);
impl WorkspacePageCursor {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded immutable page of Projects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectPageDto {
    pub(super) items: Vec<ProjectSnapshotDto>,
    pub(super) next: Option<ProjectPageCursor>,
}
impl ProjectPageDto {
    pub fn items(&self) -> &[ProjectSnapshotDto] {
        &self.items
    }
    pub fn next_cursor(&self) -> Option<&ProjectPageCursor> {
        self.next.as_ref()
    }
}

/// Bounded immutable page of Workspaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspacePageDto {
    pub(super) items: Vec<WorkspaceSnapshotDto>,
    pub(super) next: Option<WorkspacePageCursor>,
}
impl WorkspacePageDto {
    pub fn items(&self) -> &[WorkspaceSnapshotDto] {
        &self.items
    }
    pub fn next_cursor(&self) -> Option<&WorkspacePageCursor> {
        self.next.as_ref()
    }
}

/// Validated typed create request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateProjectRequest {
    pub(super) identity: CommandIdentity,
    pub(super) id: CanonicalId,
    pub(super) name: String,
}
impl CreateProjectRequest {
    pub fn new(
        identity: CommandIdentity,
        id: CanonicalId,
        name: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        Ok(Self {
            identity,
            id,
            name: display_name(name.into())?,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateWorkspaceRequest {
    pub(super) identity: CommandIdentity,
    pub(super) project_id: CanonicalId,
    pub(super) id: CanonicalId,
    pub(super) name: String,
}
impl CreateWorkspaceRequest {
    pub fn new(
        identity: CommandIdentity,
        project_id: CanonicalId,
        id: CanonicalId,
        name: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        Ok(Self {
            identity,
            project_id,
            id,
            name: display_name(name.into())?,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingProjectRequest {
    pub(super) identity: CommandIdentity,
    pub(super) id: CanonicalId,
    pub(super) expected_version: u64,
}
impl ExistingProjectRequest {
    pub fn new(
        identity: CommandIdentity,
        id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, RuntimeApiError> {
        version(expected_version)?;
        Ok(Self {
            identity,
            id,
            expected_version,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingWorkspaceRequest {
    pub(super) identity: CommandIdentity,
    pub(super) id: CanonicalId,
    pub(super) expected_version: u64,
}
impl ExistingWorkspaceRequest {
    pub fn new(
        identity: CommandIdentity,
        id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, RuntimeApiError> {
        version(expected_version)?;
        Ok(Self {
            identity,
            id,
            expected_version,
        })
    }
}

/// Move-only runtime boundary over a verified protected host transfer.
pub struct ProtectedRootAdmission(ProtectedRootBindTransport);
impl std::fmt::Debug for ProtectedRootAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedRootAdmission([REDACTED])")
    }
}
impl ProtectedRootAdmission {
    pub fn from_verified(value: ProtectedRootHandleAdmission) -> Result<Self, RuntimeApiError> {
        value
            .into_root_bind_transport()
            .map(Self)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))
    }
    pub(crate) const fn transport(&self) -> &ProtectedRootBindTransport {
        &self.0
    }
    #[must_use]
    pub const fn admission_digest(&self) -> [u8; 32] {
        self.0.admission_digest()
    }
}
#[derive(Debug)]
pub struct BindWorkspaceRootRequest<'a> {
    pub(super) identity: CommandIdentity,
    pub(super) id: CanonicalId,
    pub(super) expected_version: u64,
    pub(super) admission: &'a ProtectedRootAdmission,
}
impl<'a> BindWorkspaceRootRequest<'a> {
    pub fn new(
        identity: CommandIdentity,
        id: CanonicalId,
        expected_version: u64,
        admission: &'a ProtectedRootAdmission,
    ) -> Result<Self, RuntimeApiError> {
        version(expected_version)?;
        Ok(Self {
            identity,
            id,
            expected_version,
            admission,
        })
    }
}

fn version(value: u64) -> Result<(), RuntimeApiError> {
    (value != 0)
        .then_some(())
        .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))
}
fn display_name(value: String) -> Result<String, RuntimeApiError> {
    ProjectWorkspaceDisplayNameInput::new(value.clone())
        .map(|_| value)
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))
}
