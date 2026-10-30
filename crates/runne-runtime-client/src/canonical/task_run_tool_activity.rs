impl AuthenticatedRuntimeClient {
    /// Reads authenticated, bounded and scanned native tool observations.
    ///
    /// # Errors
    /// Returns an error for transport, authentication, malformed or mismatched responses.
    pub async fn get_task_run_tool_activity(
        &self,
        task_run_id: CanonicalId,
    ) -> Result<runne_api::TaskRunToolActivityV1, RuntimeApiError> {
        let response = self
            .authenticated_request(
                self.client
                    .get(self.url(&format!("/v1/task-runs/{task_run_id}/tools"))),
            )?
            .send()
            .await
            .map_err(map_transport)?;
        let value = read_success_json::<runne_api::TaskRunToolActivityV1>(response, &[200]).await?;
        if value.task_run_id != task_run_id.to_string()
            || value.entries.len() > 32
            || value
                .entries
                .iter()
                .any(|e| e.result_text.as_ref().is_some_and(|s| s.len() > 8192))
        {
            return Err(invalid_task_run_response());
        }
        Ok(value)
    }
}
