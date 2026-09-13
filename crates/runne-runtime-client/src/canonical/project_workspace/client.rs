use reqwest::{Method, header::CONTENT_TYPE};

use super::{
    BindWorkspaceRootRequest, CreateProjectRequest, CreateWorkspaceRequest, ExistingProjectRequest,
    ExistingWorkspaceRequest, ProjectCommandAcknowledgement, ProjectPageCursor, ProjectPageDto,
    ProjectSnapshotDto, RenameProjectRequest, WorkspaceCommandAcknowledgement, WorkspacePageCursor,
    WorkspacePageDto, WorkspaceSnapshotDto, wire::*,
};
use crate::canonical::{
    AuthenticatedRuntimeClient, CanonicalId, RuntimeApiError, RuntimeApiErrorKind,
    read_success_json,
};

impl AuthenticatedRuntimeClient {
    /// Reads one principal-bound, bounded Project page.
    pub async fn list_projects(
        &self,
        limit: u16,
        cursor: Option<&ProjectPageCursor>,
    ) -> Result<ProjectPageDto, RuntimeApiError> {
        page_limit(limit)?;
        let mut request = self
            .http_client()
            .get(self.url("/v1/projects"))
            .query(&[("limit", limit)]);
        if let Some(cursor) = cursor {
            request = request.query(&[("cursor", cursor.as_str())]);
        }
        let response = self
            .authenticated_request(request)?
            .send()
            .await
            .map_err(map_transport)?;
        project_page(
            read_success_json::<ProjectPageWire>(response, &[200]).await?,
            limit,
            &runne_api::ApiPrincipalId::new(self.session_info().principal_id.clone())
                .map_err(|_| invalid_response())?,
        )
    }
    /// Reads one Project without exposing a raw transport escape hatch.
    pub async fn get_project(
        &self,
        id: CanonicalId,
    ) -> Result<ProjectSnapshotDto, RuntimeApiError> {
        let response = self
            .authenticated_request(
                self.http_client()
                    .get(self.url(&format!("/v1/projects/{id}"))),
            )?
            .send()
            .await
            .map_err(map_transport)?;
        let snapshot = ProjectSnapshotDto::try_from(
            read_success_json::<ProjectWire>(response, &[200]).await?,
        )?;
        (snapshot.id() == id)
            .then_some(snapshot)
            .ok_or_else(invalid_response)
    }
    /// Creates one Project under authenticated command identity.
    pub async fn create_project(
        &self,
        request: CreateProjectRequest,
    ) -> Result<ProjectCommandAcknowledgement, RuntimeApiError> {
        let expected = request.id;
        let wire = CreateProjectWire {
            project_id: request.id,
            display_name: request.name,
        };
        let response = self
            .send_command("/v1/projects", &request.identity, &wire)
            .await?;
        let ack = ProjectCommandAcknowledgement::try_from(
            read_success_json::<ProjectAckWire>(response, &[202]).await?,
        )?;
        (ack.project_id() == expected && ack.new_version() == 1)
            .then_some(ack)
            .ok_or_else(invalid_response)
    }
    /// Archives one Project at its exact expected version.
    pub async fn archive_project(
        &self,
        request: ExistingProjectRequest,
    ) -> Result<ProjectCommandAcknowledgement, RuntimeApiError> {
        self.project_mutation(request, Some("archive")).await
    }
    /// Restores one archived Project at its exact expected version.
    pub async fn restore_project(
        &self,
        request: ExistingProjectRequest,
    ) -> Result<ProjectCommandAcknowledgement, RuntimeApiError> {
        self.project_mutation(request, Some("restore")).await
    }
    /// Renames one non-archived Project at its exact expected version.
    pub async fn rename_project(
        &self,
        request: RenameProjectRequest,
    ) -> Result<ProjectCommandAcknowledgement, RuntimeApiError> {
        let expected = request.id;
        let response = self
            .send_command(
                &format!("/v1/projects/{expected}/rename"),
                &request.identity,
                &RenameProjectWire {
                    expected_version: request.expected_version,
                    display_name: request.name,
                },
            )
            .await?;
        let ack = ProjectCommandAcknowledgement::try_from(
            read_success_json::<ProjectAckWire>(response, &[202]).await?,
        )?;
        (ack.project_id() == expected
            && ack.new_version()
                == request
                    .expected_version
                    .checked_add(1)
                    .ok_or_else(invalid_response)?)
            .then_some(ack)
            .ok_or_else(invalid_response)
    }
    /// Deletes one Project at its exact expected version.
    pub async fn delete_project(
        &self,
        request: ExistingProjectRequest,
    ) -> Result<ProjectCommandAcknowledgement, RuntimeApiError> {
        self.project_mutation(request, None).await
    }
    /// Reads one Project-bound, bounded Workspace page.
    pub async fn list_workspaces(
        &self,
        project_id: CanonicalId,
        limit: u16,
        cursor: Option<&WorkspacePageCursor>,
    ) -> Result<WorkspacePageDto, RuntimeApiError> {
        page_limit(limit)?;
        let mut request = self
            .http_client()
            .get(self.url(&format!("/v1/projects/{project_id}/workspaces")))
            .query(&[("limit", limit)]);
        if let Some(cursor) = cursor {
            request = request.query(&[("cursor", cursor.as_str())]);
        }
        let response = self
            .authenticated_request(request)?
            .send()
            .await
            .map_err(map_transport)?;
        let page = workspace_page(
            read_success_json::<WorkspacePageWire>(response, &[200]).await?,
            limit,
            &runne_api::ApiPrincipalId::new(self.session_info().principal_id.clone())
                .map_err(|_| invalid_response())?,
            project_id,
        )?;
        page.items()
            .iter()
            .all(|item| item.project_id() == project_id)
            .then_some(page)
            .ok_or_else(invalid_response)
    }
    /// Creates one Workspace below an existing Project.
    pub async fn create_workspace(
        &self,
        request: CreateWorkspaceRequest,
    ) -> Result<WorkspaceCommandAcknowledgement, RuntimeApiError> {
        let expected = request.id;
        let path = format!("/v1/projects/{}/workspaces", request.project_id);
        let wire = CreateWorkspaceWire {
            workspace_id: request.id,
            display_name: request.name,
        };
        let response = self.send_command(&path, &request.identity, &wire).await?;
        let ack = WorkspaceCommandAcknowledgement::try_from(
            read_success_json::<WorkspaceAckWire>(response, &[202]).await?,
        )?;
        (ack.workspace_id() == expected)
            .then_some(ack)
            .ok_or_else(invalid_response)
    }
    /// Reads one Workspace.
    pub async fn get_workspace(
        &self,
        id: CanonicalId,
    ) -> Result<WorkspaceSnapshotDto, RuntimeApiError> {
        let response = self
            .authenticated_request(
                self.http_client()
                    .get(self.url(&format!("/v1/workspaces/{id}"))),
            )?
            .send()
            .await
            .map_err(map_transport)?;
        let snapshot = WorkspaceSnapshotDto::try_from(
            read_success_json::<WorkspaceWire>(response, &[200]).await?,
        )?;
        (snapshot.id() == id)
            .then_some(snapshot)
            .ok_or_else(invalid_response)
    }
    /// Opens one Workspace at its exact expected version.
    pub async fn open_workspace(
        &self,
        request: ExistingWorkspaceRequest,
    ) -> Result<WorkspaceCommandAcknowledgement, RuntimeApiError> {
        let expected = request.id;
        let path = format!("/v1/workspaces/{expected}/open");
        let response = self
            .send_command(
                &path,
                &request.identity,
                &ExistingWire {
                    expected_version: request.expected_version,
                },
            )
            .await?;
        let ack = WorkspaceCommandAcknowledgement::try_from(
            read_success_json::<WorkspaceAckWire>(response, &[202]).await?,
        )?;
        (ack.workspace_id() == expected)
            .then_some(ack)
            .ok_or_else(invalid_response)
    }
    /// Binds only an opaque native-admission token at the exact Workspace version.
    pub async fn bind_workspace_root(
        &self,
        request: BindWorkspaceRootRequest<'_>,
    ) -> Result<WorkspaceCommandAcknowledgement, RuntimeApiError> {
        let expected = request.id;
        let path = format!("/v1/workspaces/{expected}/root-bindings");
        let wire = RootBindingWire {
            expected_version: request.expected_version,
            root_admission: request.admission.transport(),
        };
        let response = self.send_command(&path, &request.identity, &wire).await?;
        let ack = WorkspaceCommandAcknowledgement::try_from(
            read_success_json::<WorkspaceAckWire>(response, &[202]).await?,
        )?;
        (ack.workspace_id() == expected)
            .then_some(ack)
            .ok_or_else(invalid_response)
    }
    async fn project_mutation(
        &self,
        request: ExistingProjectRequest,
        operation: Option<&str>,
    ) -> Result<ProjectCommandAcknowledgement, RuntimeApiError> {
        let expected = request.id;
        let suffix = operation.map_or_else(String::new, |operation| format!("/{operation}"));
        let method = if operation.is_some() {
            Method::POST
        } else {
            Method::DELETE
        };
        let response = self
            .send_command_with_method(
                method,
                &format!("/v1/projects/{expected}{suffix}"),
                &request.identity,
                &ExistingWire {
                    expected_version: request.expected_version,
                },
            )
            .await?;
        let ack = ProjectCommandAcknowledgement::try_from(
            read_success_json::<ProjectAckWire>(response, &[202]).await?,
        )?;
        (ack.project_id() == expected)
            .then_some(ack)
            .ok_or_else(invalid_response)
    }
    async fn send_command<T: serde::Serialize>(
        &self,
        path: &str,
        identity: &crate::canonical::CommandIdentity,
        wire: &T,
    ) -> Result<reqwest::Response, RuntimeApiError> {
        self.send_command_with_method(Method::POST, path, identity, wire)
            .await
    }
    async fn send_command_with_method<T: serde::Serialize>(
        &self,
        method: Method,
        path: &str,
        identity: &crate::canonical::CommandIdentity,
        wire: &T,
    ) -> Result<reqwest::Response, RuntimeApiError> {
        let request = self.http_client().request(method, self.url(path));
        let body = serde_json::to_vec(wire).map_err(|_| invalid_request())?;
        self.command_request(request, identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)
    }
}
fn page_limit(limit: u16) -> Result<(), RuntimeApiError> {
    (limit != 0 && limit <= 100)
        .then_some(())
        .ok_or_else(invalid_request)
}
fn invalid_request() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest)
}
fn invalid_response() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)
}
fn map_transport(_: reqwest::Error) -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)
}
