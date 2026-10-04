macro_rules! remote_cancel_requested_method {
    () => {
        fn remote_cancel_requested(
            &self,
            binding: &ProviderRemoteAttemptBinding,
        ) -> Result<bool, ProviderExecutionError> {
            let connection = self
                .connection
                .lock()
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            let Some(request) = load_remote_request(&connection, binding.dispatch_attempt_id)?
            else {
                return Ok(false);
            };
            if request.binding != *binding {
                return Ok(false);
            }
            let latest: Option<Vec<u8>> = connection
                .query_row(
                    "SELECT e.payload FROM aggregate_streams s JOIN events e
           ON e.aggregate_type=1 AND e.aggregate_id=s.aggregate_id
          AND e.sequence=s.current_version
         WHERE s.aggregate_type=1 AND s.aggregate_id=?1",
                    [binding.taskrun_id.as_bytes()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            let Some(latest) = latest else {
                return Ok(false);
            };
            let latest =
                crate::codec::StoreCodec::decode(&crate::codec::TaskRunEventCodec, &latest)
                    .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
            if latest != runne_domain::task_run::TaskRunEvent::CancellationRequested {
                return Ok(false);
            }
            crate::provider::taskrun_provider_cancel_fence_matches(
                &connection,
                binding.taskrun_id,
                binding.taskrun_attempt_id,
                binding.dispatch_attempt_id,
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
        }
    };
}
