/// Runtime acknowledgement that one atomic `TaskRun` submit was durably
/// committed as a single `Created`+`Queued` unit of work.
///
/// The acknowledgement carries the exact committed identity and version for
/// reconciliation. It does not claim admission, start or completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskRunSubmitAcknowledgement {
    task_run_id: CanonicalId,
    stream_version: u64,
}

impl TaskRunSubmitAcknowledgement {
    pub(crate) const fn observed(task_run_id: CanonicalId, stream_version: u64) -> Self {
        Self {
            task_run_id,
            stream_version,
        }
    }

    #[must_use]
    pub const fn task_run_id(self) -> CanonicalId {
        self.task_run_id
    }

    #[must_use]
    pub const fn stream_version(self) -> u64 {
        self.stream_version
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskRunSubmitAcknowledgementWire {
    task_run_id: CanonicalId,
    stream_version: u64,
    transition: String,
    attempt_id: Option<CanonicalId>,
    terminal_result: Option<TaskRunTerminalResultWire>,
}

impl TryFrom<TaskRunSubmitAcknowledgementWire> for TaskRunSubmitAcknowledgement {
    type Error = RuntimeApiError;

    fn try_from(wire: TaskRunSubmitAcknowledgementWire) -> Result<Self, Self::Error> {
        if wire.stream_version != 2
            || wire.transition != "submitted"
            || wire.attempt_id.is_some()
            || wire.terminal_result.is_some()
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(Self::observed(wire.task_run_id, wire.stream_version))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitTaskRunWire {
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<SubmitProfileWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_command: Option<SubmitLocalCommandWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitLocalCommandWire {
    executable: SubmitExecutableWire,
    cwd: String,
    argv: Vec<String>,
    env: Vec<SubmitEnvironmentWire>,
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum SubmitExecutableWire {
    WorkspaceRelative(String),
    SystemProgram(String),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitEnvironmentWire {
    key: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitProfileWire {
    profile_id: String,
    profile_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitTaskRunV1Wire {
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
}

impl AuthenticatedRuntimeClient {
    /// Submits a `TaskRun` through the runtime-owned atomic submit.
    ///
    /// The runtime commits `Created`+`Queued` as one unit of work under the
    /// request's command/idempotency identity and acknowledges with the exact
    /// committed `TaskRun` identity and version. A repeated identical request
    /// returns the stored acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure when the request is
    /// rejected or the acknowledgement is not the exact expected transition.
    pub async fn submit_task_run(
        &self,
        request: SubmitTaskRunRequest,
    ) -> Result<TaskRunSubmitAcknowledgement, RuntimeApiError> {
        let input = runne_api::TaskRunInput::new(request.prompt.clone())
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let input = match request.model.clone() {
            Some(model) => input.with_requested_model(model),
            None => Ok(input),
        }
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let input = match request.selected_profile.clone() {
            Some(profile) => input.with_selected_profile(profile),
            None => Ok(input),
        }
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        if let Some(command) = request.local_command.clone() {
            input
                .with_local_command(command)
                .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        }
        if !profile3_session_matches(self.session_info())
            || !self
                .session_info()
                .capabilities
                .iter()
                .any(|cap| cap == "task_run.submit.v2")
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::Incompatible));
        }
        let url = self.url("/v2/task-runs/submit");
        let body = serde_json::to_vec(&SubmitTaskRunWire {
            conversation_id: request.conversation_id,
            workspace_id: request.workspace_id,
            prompt: request.prompt,
            model: request.model,
            profile: request.selected_profile.map(|profile| SubmitProfileWire {
                profile_id: profile.profile_id().to_owned(),
                profile_digest: hex::encode(profile.profile_digest()),
            }),
            local_command: request.local_command.map(|command| {
                let executable = match command.executable() {
                    runne_api::TaskRunExecutable::WorkspaceRelative(value) => {
                        SubmitExecutableWire::WorkspaceRelative(value.clone())
                    }
                    runne_api::TaskRunExecutable::SystemProgram(value) => {
                        SubmitExecutableWire::SystemProgram(value.clone())
                    }
                };
                SubmitLocalCommandWire {
                    executable,
                    cwd: command.cwd().to_owned(),
                    argv: command.argv().to_vec(),
                    env: command
                        .env()
                        .iter()
                        .map(|(key, value)| SubmitEnvironmentWire {
                            key: key.clone(),
                            value: value.clone(),
                        })
                        .collect(),
                }
            }),
        })
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        TaskRunSubmitAcknowledgement::try_from(
            read_success_json::<TaskRunSubmitAcknowledgementWire>(response, &[202]).await?,
        )
    }

    /// Sends the compatibility v1 IDs-only submit operation.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the profile lacks the v1 capability, the
    /// transport fails, or the acknowledgement is invalid.
    pub async fn submit_task_run_v1(
        &self,
        request: SubmitTaskRunV1Request,
    ) -> Result<TaskRunSubmitAcknowledgement, RuntimeApiError> {
        if !self
            .session_info()
            .capabilities
            .iter()
            .any(|cap| cap == "task_run.submit.v1")
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::Incompatible));
        }
        let url = self.url("/v1/task-runs/submit");
        let body = serde_json::to_vec(&SubmitTaskRunV1Wire {
            conversation_id: request.conversation_id,
            workspace_id: request.workspace_id,
        })
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        TaskRunSubmitAcknowledgement::try_from(
            read_success_json::<TaskRunSubmitAcknowledgementWire>(response, &[202]).await?,
        )
    }
}
