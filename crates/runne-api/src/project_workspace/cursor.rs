use super::{ApiPrincipalId, ProjectWorkspaceHostError};
use runne_domain::id::{ProjectId, WorkspaceId, validate_uuid_v7_bytes};
use sha2::{Digest, Sha256};

const PROJECT_CURSOR_PREFIX: &str = "runne-project-page-v1.";
const WORKSPACE_CURSOR_PREFIX: &str = "runne-workspace-page-v1.";
const PRINCIPAL_BINDING_BYTES: usize = 32;
const PROJECT_CURSOR_PAYLOAD_BYTES: usize = PRINCIPAL_BINDING_BYTES + 16;
const WORKSPACE_CURSOR_PAYLOAD_BYTES: usize = PROJECT_CURSOR_PAYLOAD_BYTES + 16;
/// Exact encoded length accepted for a Project continuation token.
pub const PROJECT_PAGE_CURSOR_TOKEN_LENGTH: usize =
    PROJECT_CURSOR_PREFIX.len() + PROJECT_CURSOR_PAYLOAD_BYTES * 2;
/// Exact encoded length accepted for a Workspace continuation token.
pub const WORKSPACE_PAGE_CURSOR_TOKEN_LENGTH: usize =
    WORKSPACE_CURSOR_PREFIX.len() + WORKSPACE_CURSOR_PAYLOAD_BYTES * 2;

/// Closed error returned when a continuation token is not canonical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageCursorTokenError {
    Invalid,
}

/// Opaque cursor for a stable Project page, bound to one authenticated principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPageCursor {
    principal_binding: [u8; PRINCIPAL_BINDING_BYTES],
    project_id: ProjectId,
}

/// Opaque cursor for a stable Workspace page, bound to one principal and Project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePageCursor {
    principal_binding: [u8; PRINCIPAL_BINDING_BYTES],
    project_id: ProjectId,
    workspace_id: WorkspaceId,
}

impl ProjectPageCursor {
    pub fn new(
        principal: ApiPrincipalId,
        project_id: ProjectId,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        valid_project_id(&project_id)?;
        Ok(Self {
            principal_binding: principal_binding(&principal),
            project_id,
        })
    }

    /// Serializes this opaque, versioned cursor for a normal-feature transport adapter.
    pub fn encode_token(&self) -> String {
        encode(
            PROJECT_CURSOR_PREFIX,
            &[&self.principal_binding, self.project_id.as_bytes()],
        )
    }

    /// Decodes exactly one canonical Project cursor token.
    pub fn decode_token(token: &str) -> Result<Self, PageCursorTokenError> {
        let fields = decode(token, PROJECT_CURSOR_PREFIX, PROJECT_CURSOR_PAYLOAD_BYTES)?;
        let project_id = ProjectId::from_bytes(
            fields[32..48]
                .try_into()
                .map_err(|_| PageCursorTokenError::Invalid)?,
        );
        valid_project_id_token(&project_id)?;
        Ok(Self {
            principal_binding: fields[..32]
                .try_into()
                .map_err(|_| PageCursorTokenError::Invalid)?,
            project_id,
        })
    }

    pub fn parts_for_principal(
        &self,
        principal: &ApiPrincipalId,
    ) -> Result<ProjectId, ProjectWorkspaceHostError> {
        (self.principal_binding == principal_binding(principal))
            .then_some(self.project_id)
            .ok_or(ProjectWorkspaceHostError::NotFound)
    }
}

impl WorkspacePageCursor {
    pub fn new(
        principal: ApiPrincipalId,
        project_id: ProjectId,
        workspace_id: WorkspaceId,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        valid_project_id(&project_id)?;
        valid_workspace_id(&workspace_id)?;
        Ok(Self {
            principal_binding: principal_binding(&principal),
            project_id,
            workspace_id,
        })
    }

    /// Serializes this opaque, versioned cursor for a normal-feature transport adapter.
    pub fn encode_token(&self) -> String {
        encode(
            WORKSPACE_CURSOR_PREFIX,
            &[
                &self.principal_binding,
                self.project_id.as_bytes(),
                self.workspace_id.as_bytes(),
            ],
        )
    }

    /// Decodes exactly one canonical Workspace cursor token.
    pub fn decode_token(token: &str) -> Result<Self, PageCursorTokenError> {
        let fields = decode(
            token,
            WORKSPACE_CURSOR_PREFIX,
            WORKSPACE_CURSOR_PAYLOAD_BYTES,
        )?;
        let project_id = ProjectId::from_bytes(
            fields[32..48]
                .try_into()
                .map_err(|_| PageCursorTokenError::Invalid)?,
        );
        let workspace_id = WorkspaceId::from_bytes(
            fields[48..64]
                .try_into()
                .map_err(|_| PageCursorTokenError::Invalid)?,
        );
        valid_project_id_token(&project_id)?;
        valid_workspace_id_token(&workspace_id)?;
        Ok(Self {
            principal_binding: fields[..32]
                .try_into()
                .map_err(|_| PageCursorTokenError::Invalid)?,
            project_id,
            workspace_id,
        })
    }

    pub fn parts_for_principal(
        &self,
        principal: &ApiPrincipalId,
        project_id: ProjectId,
    ) -> Result<WorkspaceId, ProjectWorkspaceHostError> {
        (self.principal_binding == principal_binding(principal) && self.project_id == project_id)
            .then_some(self.workspace_id)
            .ok_or(ProjectWorkspaceHostError::NotFound)
    }
}

fn principal_binding(principal: &ApiPrincipalId) -> [u8; PRINCIPAL_BINDING_BYTES] {
    let mut digest = Sha256::new();
    digest.update(b"runne.project-workspace-page-cursor.principal.v1\0");
    digest.update(principal.as_str().as_bytes());
    digest.finalize().into()
}

fn valid_project_id(id: &ProjectId) -> Result<(), ProjectWorkspaceHostError> {
    validate_uuid_v7_bytes(id.as_bytes()).map_err(|_| ProjectWorkspaceHostError::InvariantViolation)
}

fn valid_workspace_id(id: &WorkspaceId) -> Result<(), ProjectWorkspaceHostError> {
    validate_uuid_v7_bytes(id.as_bytes()).map_err(|_| ProjectWorkspaceHostError::InvariantViolation)
}

fn valid_project_id_token(id: &ProjectId) -> Result<(), PageCursorTokenError> {
    validate_uuid_v7_bytes(id.as_bytes()).map_err(|_| PageCursorTokenError::Invalid)
}

fn valid_workspace_id_token(id: &WorkspaceId) -> Result<(), PageCursorTokenError> {
    validate_uuid_v7_bytes(id.as_bytes()).map_err(|_| PageCursorTokenError::Invalid)
}

fn encode(prefix: &str, fields: &[&[u8]]) -> String {
    let mut token = String::with_capacity(
        prefix.len() + fields.iter().map(|field| field.len() * 2).sum::<usize>(),
    );
    token.push_str(prefix);
    for field in fields {
        for byte in *field {
            token.push_str(&format!("{byte:02x}"));
        }
    }
    token
}

fn decode(
    token: &str,
    prefix: &str,
    payload_length: usize,
) -> Result<Vec<u8>, PageCursorTokenError> {
    if token.len() != prefix.len() + payload_length * 2 || !token.starts_with(prefix) {
        return Err(PageCursorTokenError::Invalid);
    }
    let encoded = &token.as_bytes()[prefix.len()..];
    (0..payload_length)
        .map(|index| {
            hex_byte(encoded[index * 2], encoded[index * 2 + 1])
                .ok_or(PageCursorTokenError::Invalid)
        })
        .collect()
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_nibble(high)? << 4 | hex_nibble(low)?)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
