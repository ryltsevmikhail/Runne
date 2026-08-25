/// Capability required before process lifecycle calls are issued.
pub const PROCESS_CONTROL_CAPABILITY_V1: &str = runne_api::PROCESS_CONTROL_CAPABILITY_V1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessStateDto { Starting, Running, Stopping, Exited, Failed }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutputStreamDto { Stdout, Stderr }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutputChunkDto { sequence: u64, stream: ProcessOutputStreamDto, text: String }
impl ProcessOutputChunkDto {
    #[must_use] pub const fn sequence(&self) -> u64 { self.sequence }
    #[must_use] pub const fn stream(&self) -> ProcessOutputStreamDto { self.stream }
    #[must_use] pub fn text(&self) -> &str { &self.text }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutputPageDto { chunks: Vec<ProcessOutputChunkDto> }
impl ProcessOutputPageDto {
    #[must_use] pub fn chunks(&self) -> &[ProcessOutputChunkDto] { &self.chunks }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessSnapshotDto {
    process_id: CanonicalId,
    invocation_id: CanonicalId,
    workspace_id: CanonicalId,
    state: ProcessStateDto,
    version: u64,
    next_output_sequence: u64,
}
impl ProcessSnapshotDto {
    #[must_use] pub const fn process_id(self) -> CanonicalId { self.process_id }
    #[must_use] pub const fn invocation_id(self) -> CanonicalId { self.invocation_id }
    #[must_use] pub const fn workspace_id(self) -> CanonicalId { self.workspace_id }
    #[must_use] pub const fn state(self) -> ProcessStateDto { self.state }
    #[must_use] pub const fn version(self) -> u64 { self.version }
    #[must_use] pub const fn next_output_sequence(self) -> u64 { self.next_output_sequence }
}

/// Runtime-owned invocation request; it contains no executable path or raw OS handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartProcessRequest {
    pub(crate) identity: CommandIdentity,
    workspace_id: CanonicalId,
    task_run_id: CanonicalId,
    attempt_id: CanonicalId,
    invocation_id: CanonicalId,
}
impl StartProcessRequest {
    #[must_use]
    pub const fn new(identity: CommandIdentity, workspace_id: CanonicalId, task_run_id: CanonicalId, attempt_id: CanonicalId, invocation_id: CanonicalId) -> Self {
        Self { identity, workspace_id, task_run_id, attempt_id, invocation_id }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopProcessRequest {
    pub(crate) identity: CommandIdentity,
    process_id: CanonicalId,
    expected_version: u64,
}
impl StopProcessRequest {
    #[must_use]
    pub const fn new(identity: CommandIdentity, process_id: CanonicalId, expected_version: u64) -> Self {
        Self { identity, process_id, expected_version }
    }
}

impl AuthenticatedRuntimeClient {
    /// Starts one runtime-prepared process invocation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the capability is absent, transport fails,
    /// or the runtime returns an invalid snapshot.
    pub async fn start_process(&self, request: StartProcessRequest) -> Result<ProcessSnapshotDto, RuntimeApiError> {
        require_capability(self, PROCESS_CONTROL_CAPABILITY_V1)?;
        let body = serde_json::to_vec(&StartProcessWire {
            workspace_id: request.workspace_id,
            task_run_id: request.task_run_id,
            attempt_id: request.attempt_id,
            invocation_id: request.invocation_id,
        }).map_err(|_| invalid_request())?;
        let response = self.command_request(self.client.post(self.url("/v1/processes")), &request.identity)?
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body).send().await.map_err(map_transport)?;
        let snapshot = ProcessSnapshotDto::try_from(read_success_json::<SnapshotWire>(response, &[202]).await?)?;
        (snapshot.workspace_id == request.workspace_id && snapshot.invocation_id == request.invocation_id)
            .then_some(snapshot).ok_or_else(invalid_response)
    }

    /// Reads one runtime-owned process snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the capability is absent, transport fails,
    /// or the runtime returns an invalid snapshot.
    pub async fn get_process(&self, process_id: CanonicalId) -> Result<ProcessSnapshotDto, RuntimeApiError> {
        require_capability(self, PROCESS_CONTROL_CAPABILITY_V1)?;
        let response = self.authenticated_request(self.client.get(self.url(&format!("/v1/processes/{process_id}"))))?
            .send().await.map_err(map_transport)?;
        let snapshot = ProcessSnapshotDto::try_from(read_success_json::<SnapshotWire>(response, &[200]).await?)?;
        (snapshot.process_id == process_id).then_some(snapshot).ok_or_else(invalid_response)
    }

    /// Reads a bounded, sanitized output page after a sequence cursor.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the capability is absent, the limit is
    /// invalid, transport fails, or output violates the canonical contract.
    pub async fn read_process_output(&self, process_id: CanonicalId, after_sequence: u64, limit: u16) -> Result<ProcessOutputPageDto, RuntimeApiError> {
        require_capability(self, PROCESS_CONTROL_CAPABILITY_V1)?;
        if limit == 0 || limit > runne_api::MAX_PROCESS_OUTPUT_CHUNKS { return Err(invalid_request()); }
        let response = self.authenticated_request(self.client.get(self.url(&format!("/v1/processes/{process_id}/output")))
            .query(&[("afterSequence", after_sequence.to_string()), ("limit", limit.to_string())]))?
            .send().await.map_err(map_transport)?;
        let page = ProcessOutputPageDto::try_from(read_success_json::<OutputPageWire>(response, &[200]).await?)?;
        (page.chunks.len() <= usize::from(limit)).then_some(page).ok_or_else(invalid_response)
    }

    /// Requests a stop for one exact process version.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the capability is absent, transport fails,
    /// or the runtime returns an invalid snapshot.
    pub async fn stop_process(&self, request: StopProcessRequest) -> Result<ProcessSnapshotDto, RuntimeApiError> {
        require_capability(self, PROCESS_CONTROL_CAPABILITY_V1)?;
        let body = serde_json::to_vec(&ExistingProcessWire { expected_version: request.expected_version })
            .map_err(|_| invalid_request())?;
        let response = self.command_request(self.client.post(self.url(&format!("/v1/processes/{}/stop", request.process_id))), &request.identity)?
            .header(reqwest::header::CONTENT_TYPE, "application/json").body(body)
            .send().await.map_err(map_transport)?;
        let snapshot = ProcessSnapshotDto::try_from(read_success_json::<SnapshotWire>(response, &[202]).await?)?;
        (snapshot.process_id == request.process_id).then_some(snapshot).ok_or_else(invalid_response)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
struct StartProcessWire { workspace_id: CanonicalId, task_run_id: CanonicalId, attempt_id: CanonicalId, invocation_id: CanonicalId }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExistingProcessWire { expected_version: u64 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotWire { process_id: CanonicalId, invocation_id: CanonicalId, workspace_id: CanonicalId, state: ProcessStateWire, version: u64, next_output_sequence: u64 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OutputPageWire { chunks: Vec<OutputChunkWire> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OutputChunkWire { sequence: u64, stream: ProcessOutputStreamWire, text: String }
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessStateWire { Starting, Running, Stopping, Exited, Failed }
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessOutputStreamWire { Stdout, Stderr }

impl TryFrom<SnapshotWire> for ProcessSnapshotDto {
    type Error = RuntimeApiError;
    fn try_from(value: SnapshotWire) -> Result<Self, Self::Error> {
        if value.version == 0 || value.next_output_sequence == 0 { return Err(invalid_response()); }
        Ok(Self { process_id: value.process_id, invocation_id: value.invocation_id, workspace_id: value.workspace_id, state: value.state.into(), version: value.version, next_output_sequence: value.next_output_sequence })
    }
}
impl TryFrom<OutputPageWire> for ProcessOutputPageDto {
    type Error = RuntimeApiError;
    fn try_from(value: OutputPageWire) -> Result<Self, Self::Error> {
        let chunks = value.chunks.into_iter().map(|chunk| {
            let stream = match chunk.stream { ProcessOutputStreamWire::Stdout => runne_api::ProcessOutputStream::Stdout, ProcessOutputStreamWire::Stderr => runne_api::ProcessOutputStream::Stderr };
            runne_api::ProcessOutputChunk::new(chunk.sequence, stream, chunk.text.clone()).map_err(|_| invalid_response())?;
            Ok(ProcessOutputChunkDto { sequence: chunk.sequence, stream: chunk.stream.into(), text: chunk.text })
        }).collect::<Result<Vec<_>, RuntimeApiError>>()?;
    runne_api::ProcessOutputPage::new(runne_api::MAX_PROCESS_OUTPUT_CHUNKS, chunks.iter().map(|chunk| runne_api::ProcessOutputChunk::new(chunk.sequence, api_stream(chunk.stream), chunk.text.clone()).map_err(|_| invalid_response())).collect::<Result<Vec<_>, _>>()?)
            .map_err(|_| invalid_response())?;
        Ok(Self { chunks })
    }
}
impl From<ProcessStateWire> for ProcessStateDto {
    fn from(value: ProcessStateWire) -> Self { match value { ProcessStateWire::Starting => Self::Starting, ProcessStateWire::Running => Self::Running, ProcessStateWire::Stopping => Self::Stopping, ProcessStateWire::Exited => Self::Exited, ProcessStateWire::Failed => Self::Failed } }
}
impl From<ProcessOutputStreamWire> for ProcessOutputStreamDto {
    fn from(value: ProcessOutputStreamWire) -> Self { match value { ProcessOutputStreamWire::Stdout => Self::Stdout, ProcessOutputStreamWire::Stderr => Self::Stderr } }
}

const fn api_stream(value: ProcessOutputStreamDto) -> runne_api::ProcessOutputStream {
    match value {
        ProcessOutputStreamDto::Stdout => runne_api::ProcessOutputStream::Stdout,
        ProcessOutputStreamDto::Stderr => runne_api::ProcessOutputStream::Stderr,
    }
}
