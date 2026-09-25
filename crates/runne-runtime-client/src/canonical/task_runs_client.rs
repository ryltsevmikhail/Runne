impl AuthenticatedRuntimeClient {
    /// Reads the authoritative committed `TaskRun` snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn get_task_run(
        &self,
        task_run_id: CanonicalId,
    ) -> Result<TaskRunSnapshot, RuntimeApiError> {
        let url = self.url(&format!("/v1/task-runs/{task_run_id}"));
        let response = self
            .authenticated_request(self.client.get(url))?
            .send()
            .await
            .map_err(map_transport)?;
        let snapshot = TaskRunSnapshot::try_from(
            read_success_json::<TaskRunSnapshotWire>(response, &[200]).await?,
        )?;
        if snapshot.task_run_id() != task_run_id {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(snapshot)
    }

    /// Reads every authoritative `TaskRun` snapshot for lifecycle decisions.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure when the list cannot be
    /// read or contains an invalid canonical snapshot.
    pub async fn list_task_runs(&self) -> Result<Vec<TaskRunSnapshot>, RuntimeApiError> {
        let response = self
            .authenticated_request(self.client.get(self.url("/v1/task-runs")))?
            .send()
            .await
            .map_err(map_transport)?;
        let wire: TaskRunListWire = read_success_json(response, &[200]).await?;
        decode_task_run_list(wire)
    }

    /// Requests durable cancellation of an authoritative `TaskRun`.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure when the request is
    /// rejected or the acknowledgement is not the exact expected transition.
    pub async fn cancel_task_run(
        &self,
        request: CancelTaskRunRequest,
    ) -> Result<TaskRunCancellationAcknowledgement, RuntimeApiError> {
        let expected_task_run_id = request.task_run_id;
        let expected_stream_version = request
            .expected_version
            .checked_add(1)
            .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let url = self.url(&format!("/v1/task-runs/{}/cancel", request.task_run_id));
        let body = serde_json::to_vec(&ExistingTaskRunWire {
            expected_version: request.expected_version,
        })
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let acknowledgement = TaskRunCancellationAcknowledgement::try_from(
            read_success_json::<TaskRunCancellationAcknowledgementWire>(response, &[202]).await?,
        )?;
        if acknowledgement.task_run_id() != expected_task_run_id
            || acknowledgement.stream_version() != expected_stream_version
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(acknowledgement)
    }

}
