impl AuthenticatedRuntimeClient {
    /// Reads versioned `TaskRun` effects without changing the legacy snapshot response.
    ///
    /// # Errors
    ///
    /// Returns an error when transport, authentication, decoding, or response
    /// correlation fails.
    pub async fn get_task_run_effects(
        &self,
        task_run_id: CanonicalId,
    ) -> Result<TaskRunEffectsV1, RuntimeApiError> {
        let response = self
            .authenticated_request(
                self.client
                    .get(self.url(&format!("/v1/task-runs/{task_run_id}/effects"))),
            )?
            .send()
            .await
            .map_err(map_transport)?;
        let effects = TaskRunEffectsV1::try_from(
            read_success_json::<TaskRunEffectsWire>(response, &[200]).await?,
        )?;
        if effects.task_run_id() != task_run_id {
            return Err(invalid_task_run_response());
        }
        Ok(effects)
    }
}
