impl AppCore {
    /// Starts one runtime-prepared process invocation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid IDs, unavailable runtime, or an
    /// unpublished process capability.
    pub async fn start_process(
        &self,
        workspace_id: &str,
        task_run_id: &str,
        attempt_id: &str,
        invocation_id: &str,
    ) -> Result<CanonicalProcessSnapshot, AppCoreError> {
        let workspace_id = parse_process_id(workspace_id)?;
        let task_run_id = parse_process_id(task_run_id)?;
        let attempt_id = parse_process_id(attempt_id)?;
        let invocation_id = parse_process_id(invocation_id)?;
        let identity = process_command_identity()?;
        let _operation = self.runtime_operation.lock().await;
        let snapshot = self
            .live_runtime_client()?
            .start_process(StartProcessRequest::new(
                identity,
                workspace_id,
                task_run_id,
                attempt_id,
                invocation_id,
            ))
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalProcessSnapshot::from(&snapshot))
    }

    /// Reads one authenticated runtime-owned process snapshot.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an invalid process ID or unavailable runtime.
    pub async fn get_process(
        &self,
        process_id: &str,
    ) -> Result<CanonicalProcessSnapshot, AppCoreError> {
        let process_id = parse_process_id(process_id)?;
        let _operation = self.runtime_operation.lock().await;
        let snapshot = self
            .live_runtime_client()?
            .get_process(process_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalProcessSnapshot::from(&snapshot))
    }

    /// Reads one bounded sanitized process-output page.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an invalid process ID, limit, or unavailable runtime.
    pub async fn read_process_output(
        &self,
        process_id: &str,
        after_sequence: u64,
        limit: u16,
    ) -> Result<CanonicalProcessOutputPage, AppCoreError> {
        let process_id = parse_process_id(process_id)?;
        let _operation = self.runtime_operation.lock().await;
        let page = self
            .live_runtime_client()?
            .read_process_output(process_id, after_sequence, limit)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalProcessOutputPage::from(&page))
    }

    /// Requests a stop for one exact runtime-owned process version.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an invalid process ID/version or unavailable runtime.
    pub async fn stop_process(
        &self,
        process_id: &str,
        expected_version: u64,
    ) -> Result<CanonicalProcessSnapshot, AppCoreError> {
        let process_id = parse_process_id(process_id)?;
        let identity = process_command_identity()?;
        let _operation = self.runtime_operation.lock().await;
        let snapshot = self
            .live_runtime_client()?
            .stop_process(StopProcessRequest::new(identity, process_id, expected_version))
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalProcessSnapshot::from(&snapshot))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalProcessSnapshot {
    pub process_id: String,
    pub invocation_id: String,
    pub workspace_id: String,
    pub state: CanonicalProcessState,
    pub version: u64,
    pub next_output_sequence: u64,
}

impl From<&ProcessSnapshotDto> for CanonicalProcessSnapshot {
    fn from(value: &ProcessSnapshotDto) -> Self {
        Self {
            process_id: value.process_id().to_string(),
            invocation_id: value.invocation_id().to_string(),
            workspace_id: value.workspace_id().to_string(),
            state: CanonicalProcessState::from(value.state()),
            version: value.version(),
            next_output_sequence: value.next_output_sequence(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalProcessState { Starting, Running, Stopping, Exited, Failed }

impl From<ProcessStateDto> for CanonicalProcessState {
    fn from(value: ProcessStateDto) -> Self {
        match value {
            ProcessStateDto::Starting => Self::Starting,
            ProcessStateDto::Running => Self::Running,
            ProcessStateDto::Stopping => Self::Stopping,
            ProcessStateDto::Exited => Self::Exited,
            ProcessStateDto::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalProcessOutputPage { pub chunks: Vec<CanonicalProcessOutputChunk> }

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalProcessOutputChunk {
    pub sequence: u64,
    pub stream: CanonicalProcessOutputStream,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalProcessOutputStream { Stdout, Stderr }

impl From<&ProcessOutputPageDto> for CanonicalProcessOutputPage {
    fn from(value: &ProcessOutputPageDto) -> Self {
        Self {
            chunks: value.chunks().iter().map(CanonicalProcessOutputChunk::from).collect(),
        }
    }
}

impl From<&runne_runtime_client::ProcessOutputChunkDto> for CanonicalProcessOutputChunk {
    fn from(value: &runne_runtime_client::ProcessOutputChunkDto) -> Self {
        Self {
            sequence: value.sequence(),
            stream: CanonicalProcessOutputStream::from(value.stream()),
            text: value.text().to_owned(),
        }
    }
}

impl From<ProcessOutputStreamDto> for CanonicalProcessOutputStream {
    fn from(value: ProcessOutputStreamDto) -> Self {
        match value { ProcessOutputStreamDto::Stdout => Self::Stdout, ProcessOutputStreamDto::Stderr => Self::Stderr }
    }
}

fn parse_process_id(value: &str) -> Result<CanonicalId, AppCoreError> {
    CanonicalId::parse(value).map_err(|_| AppCoreError::InvalidMutation)
}

fn process_command_identity() -> Result<CommandIdentity, AppCoreError> {
    let command_id = CanonicalId::now_v7();
    CommandIdentity::new(command_id, command_id.to_string()).map_err(|_| AppCoreError::InvalidMutation)
}
