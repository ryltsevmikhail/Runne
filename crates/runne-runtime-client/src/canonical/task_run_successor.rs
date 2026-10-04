/// Closed duplicate-execution and cost acknowledgment for an unknown `TaskRun`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownSuccessorAcknowledgment {
    DuplicateExecutionAndCostV1,
}

/// Explicit successor request. It carries no replacement prompt or route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersedeUnknownTaskRunRequest {
    pub(crate) identity: CommandIdentity,
    pub(crate) predecessor_task_run_id: CanonicalId,
    pub(crate) expected_version: u64,
    acknowledgment: UnknownSuccessorAcknowledgment,
}

impl SupersedeUnknownTaskRunRequest {
    /// Builds the only currently supported unknown-outcome acknowledgment.
    #[must_use]
    pub const fn duplicate_execution_and_cost_v1(
        identity: CommandIdentity,
        predecessor_task_run_id: CanonicalId,
        expected_version: u64,
    ) -> Self {
        Self {
            identity,
            predecessor_task_run_id,
            expected_version,
            acknowledgment: UnknownSuccessorAcknowledgment::DuplicateExecutionAndCostV1,
        }
    }
}

/// Exact durable successor identity returned by the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskRunSuccessorAcknowledgement {
    predecessor_task_run_id: CanonicalId,
    successor_task_run_id: CanonicalId,
    predecessor_version: u64,
    stream_version: u64,
}

impl TaskRunSuccessorAcknowledgement {
    pub(crate) const fn observed(
        predecessor_task_run_id: CanonicalId,
        successor_task_run_id: CanonicalId,
        predecessor_version: u64,
        stream_version: u64,
    ) -> Self {
        Self {
            predecessor_task_run_id,
            successor_task_run_id,
            predecessor_version,
            stream_version,
        }
    }
    #[must_use]
    pub const fn predecessor_task_run_id(self) -> CanonicalId {
        self.predecessor_task_run_id
    }

    #[must_use]
    pub const fn successor_task_run_id(self) -> CanonicalId {
        self.successor_task_run_id
    }

    #[must_use]
    pub const fn predecessor_version(self) -> u64 {
        self.predecessor_version
    }

    #[must_use]
    pub const fn stream_version(self) -> u64 {
        self.stream_version
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnknownSuccessorWire {
    expected_version: u64,
    acknowledgment: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskRunSuccessorWire {
    predecessor_task_run_id: CanonicalId,
    task_run_id: CanonicalId,
    predecessor_version: u64,
    stream_version: u64,
    transition: String,
    attempt_id: Option<CanonicalId>,
    terminal_result: Option<TaskRunTerminalResultWire>,
}

impl AuthenticatedRuntimeClient {
    /// Creates a linked successor after the caller has explicitly accepted
    /// possible duplicate remote execution and charges.
    ///
    /// # Errors
    ///
    /// Returns an error when transport, authentication, decoding, or response
    /// correlation fails.
    pub async fn supersede_unknown_task_run(
        &self,
        request: SupersedeUnknownTaskRunRequest,
    ) -> Result<TaskRunSuccessorAcknowledgement, RuntimeApiError> {
        let predecessor = request.predecessor_task_run_id;
        let wire = UnknownSuccessorWire {
            expected_version: request.expected_version,
            acknowledgment: match request.acknowledgment {
                UnknownSuccessorAcknowledgment::DuplicateExecutionAndCostV1 => {
                    "duplicate_execution_and_cost_v1"
                }
            },
        };
        let body = serde_json::to_vec(&wire)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let url = self.url(&format!("/v1/task-runs/{predecessor}/successor"));
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let wire: TaskRunSuccessorWire = read_success_json(response, &[202]).await?;
        if wire.predecessor_task_run_id != predecessor
            || wire.task_run_id == predecessor
            || wire.stream_version != 2
            || !(wire.predecessor_version == request.expected_version
                || request.expected_version.checked_add(1) == Some(wire.predecessor_version))
            || wire.transition != "unknown_successor_created"
            || wire.attempt_id.is_some()
            || wire.terminal_result.is_some()
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(TaskRunSuccessorAcknowledgement {
            predecessor_task_run_id: predecessor,
            successor_task_run_id: wire.task_run_id,
            predecessor_version: wire.predecessor_version,
            stream_version: wire.stream_version,
        })
    }
}
