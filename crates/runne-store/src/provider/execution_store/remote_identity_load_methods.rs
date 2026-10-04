macro_rules! remote_identity_load_methods {
    () => {
        fn load_remote_identity(
            &self,
            attempt: DispatchAttemptId,
        ) -> Result<
            Option<(
                ProviderRemoteRequestIntent,
                Option<ProviderRemoteIdentityRecord>,
            )>,
            ProviderExecutionError,
        > {
            let connection = self
                .connection
                .lock()
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            let request = load_remote_request(&connection, attempt)?;
            let Some(request) = request else {
                return Ok(None);
            };
            let response = load_remote_response(&connection, attempt)?;
            Ok(Some((request, response)))
        }

        fn load_remote_terminal_artifact(
            &self,
            attempt: DispatchAttemptId,
        ) -> Result<
            Option<runne_application::provider::ProviderRemoteTerminalRecord>,
            ProviderExecutionError,
        > {
            read_remote_terminal_artifact(self, attempt)
        }

        fn load_remote_attempt(
            &self,
            attempt: DispatchAttemptId,
        ) -> Result<
            Option<runne_application::provider::ProviderRemoteAttemptRecord>,
            ProviderExecutionError,
        > {
            read_remote_attempt_snapshot(self, attempt)
        }
    };
}
