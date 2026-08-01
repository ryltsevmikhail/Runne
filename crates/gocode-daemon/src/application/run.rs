impl DaemonApplication {
    /// Runs until shutdown or HTTP failure, then stops HTTP before the
    /// canonical runtime and releases bootstrap resources last.
    pub async fn run<F>(self, shutdown: F) -> Result<(), DaemonError>
    where
        F: Future<Output = Result<(), DaemonError>>,
    {
        let Self {
            bootstrap,
            store,
            http_host,
            client_profile,
            binding,
            local_session_service,
            session_clock,
            protected_activation,
            mut runtime_controller,
            _secret_broker,
            task_supervisor,
            shutdown_timeout,
        } = self;

        let http_result = http_host.start().run_until(shutdown).await;
        let drain_result =
            graceful_shutdown(&task_supervisor, duration_millis(shutdown_timeout)).await;
        let http_result = combine_shutdown_results(http_result, drain_result);
        let runtime_result = shutdown_runtime(&mut runtime_controller, shutdown_timeout).await;

        drop(client_profile);
        drop(binding);
        drop(local_session_service);
        drop(session_clock);
        let _ = protected_activation;
        drop(_secret_broker);
        drop(store);
        drop(bootstrap);

        combine_shutdown_results(http_result, runtime_result)
    }

}
