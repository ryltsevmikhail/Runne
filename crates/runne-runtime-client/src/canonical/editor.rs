/// Capability required before scoped editor activation is issued.
pub const WORKSPACE_EDITOR_CAPABILITY_V1: &str = runne_api::WORKSPACE_EDITOR_CAPABILITY_V1;

/// Closed target selector accepted by the renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditorLaunchTargetDto {
    SystemDefault,
}

/// Runtime command identity and a bounded Workspace-relative editor reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenEditorCommandRequest {
    pub(crate) identity: CommandIdentity,
    workspace_id: CanonicalId,
    relative_path: String,
    target: EditorLaunchTargetDto,
}

impl OpenEditorCommandRequest {
    /// Creates a command request after validating the closed path grammar.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request error when the Workspace identifier or
    /// relative path does not satisfy the public contract.
    pub fn new(
        identity: CommandIdentity,
        workspace_id: CanonicalId,
        relative_path: impl Into<String>,
        target: EditorLaunchTargetDto,
    ) -> Result<Self, RuntimeApiError> {
        let relative_path = relative_path.into();
        let workspace_id_domain = workspace_id
            .to_string()
            .parse()
            .map_err(|_| invalid_request())?;
        runne_api::OpenEditorRequest::new(
            workspace_id_domain,
            relative_path.clone(),
            runne_api::EditorLaunchTargetV1::SystemDefault,
        )
        .map_err(|_| invalid_request())?;
        Ok(Self {
            identity,
            workspace_id,
            relative_path,
            target,
        })
    }
}

/// Acknowledgement after the runtime accepted the native editor action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EditorLaunchReceiptDto {
    workspace_id: CanonicalId,
}

impl EditorLaunchReceiptDto {
    /// Returns the affected Workspace.
    #[must_use]
    pub const fn workspace_id(self) -> CanonicalId {
        self.workspace_id
    }
}

impl AuthenticatedRuntimeClient {
    /// Opens one runtime-authorized Workspace-relative file in the system default editor.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability is absent, transport fails, the
    /// runtime rejects the command, or the receipt is not an exact match.
    pub async fn open_workspace_editor(
        &self,
        request: OpenEditorCommandRequest,
    ) -> Result<EditorLaunchReceiptDto, RuntimeApiError> {
        require_capability(self, WORKSPACE_EDITOR_CAPABILITY_V1)?;
        let response = self
            .command_request(
                self.client
                    .post(self.url(&format!("/v1/workspaces/{}/editor", request.workspace_id))),
                &request.identity,
            )?
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&OpenEditorWire {
                    relative_path: &request.relative_path,
                    target: request.target,
                })
                .map_err(|_| invalid_request())?,
            )
            .send()
            .await
            .map_err(map_transport)?;
        let wire: EditorReceiptWire = read_success_json(response, &[202]).await?;
        let workspace_id =
            CanonicalId::parse(&wire.workspace_id).map_err(|_| invalid_response())?;
        (wire.target == "system_default" && workspace_id == request.workspace_id)
            .then_some(EditorLaunchReceiptDto { workspace_id })
            .ok_or_else(invalid_response)
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenEditorWire<'a> {
    relative_path: &'a str,
    target: EditorLaunchTargetDto,
}

impl serde::Serialize for EditorLaunchTargetDto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::SystemDefault => "system_default",
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EditorReceiptWire {
    workspace_id: String,
    target: String,
}
