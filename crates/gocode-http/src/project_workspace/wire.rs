use gocode_api::{
    ProjectCommandAck, ProjectPage, ProjectSnapshot, RootBindAdmission, WorkspaceCommandAck,
    WorkspacePage, WorkspaceSnapshot,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CreateProjectBody {
    pub project_id: String,
    pub display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CreateWorkspaceBody {
    pub workspace_id: String,
    pub display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExistingBody {
    pub expected_version: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RootBindingBody {
    pub expected_version: u64,
    pub root_admission: RootBindAdmission,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PageQuery {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProjectWire {
    project_id: String,
    display_name: String,
    version: u64,
    archived: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WorkspaceWire {
    workspace_id: String,
    project_id: String,
    display_name: String,
    version: u64,
    open: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProjectAckWire {
    project_id: String,
    new_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WorkspaceAckWire {
    workspace_id: String,
    new_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProjectPageWire {
    items: Vec<ProjectWire>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WorkspacePageWire {
    items: Vec<WorkspaceWire>,
    next_cursor: Option<String>,
}

impl From<ProjectSnapshot> for ProjectWire {
    fn from(value: ProjectSnapshot) -> Self {
        Self {
            project_id: value.project_id.to_string(),
            display_name: value.display_name,
            version: value.version,
            archived: value.archived,
        }
    }
}
impl From<WorkspaceSnapshot> for WorkspaceWire {
    fn from(value: WorkspaceSnapshot) -> Self {
        Self {
            workspace_id: value.workspace_id.to_string(),
            project_id: value.project_id.to_string(),
            display_name: value.display_name,
            version: value.version,
            open: value.open,
        }
    }
}
impl From<ProjectCommandAck> for ProjectAckWire {
    fn from(value: ProjectCommandAck) -> Self {
        Self {
            project_id: value.project_id.to_string(),
            new_version: value.new_version,
        }
    }
}
impl From<WorkspaceCommandAck> for WorkspaceAckWire {
    fn from(value: WorkspaceCommandAck) -> Self {
        Self {
            workspace_id: value.workspace_id.to_string(),
            new_version: value.new_version,
        }
    }
}
impl From<ProjectPage> for ProjectPageWire {
    fn from(value: ProjectPage) -> Self {
        Self {
            items: value.items().iter().cloned().map(Into::into).collect(),
            next_cursor: value.next_cursor().map(|value| value.encode_token()),
        }
    }
}
impl From<WorkspacePage> for WorkspacePageWire {
    fn from(value: WorkspacePage) -> Self {
        Self {
            items: value.items().iter().cloned().map(Into::into).collect(),
            next_cursor: value.next_cursor().map(|value| value.encode_token()),
        }
    }
}
