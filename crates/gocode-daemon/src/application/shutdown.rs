use super::*;

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
            provider_activation,
            runtime_liveness,
            mut runtime_controller,
            _secret_broker,
            task_supervisor,
            shutdown_timeout,
            #[cfg(feature = "desktop-protected")]
            root_control,
            runtime_capabilities,
        } = self;

        let http_result = http_host.start().run_until(shutdown).await;
        let drain_result =
            graceful_shutdown(&task_supervisor, duration_millis(shutdown_timeout)).await;
        let http_result = combine_shutdown_results(http_result, drain_result);
        let runtime_result = shutdown_runtime(&mut runtime_controller, shutdown_timeout).await;
        drop(runtime_liveness);

        drop(client_profile);
        drop(binding);
        drop(local_session_service);
        drop(session_clock);
        #[cfg(feature = "desktop-protected")]
        if let Some(control) = root_control {
            control.shutdown();
        }
        let _ = protected_activation;
        let _ = runtime_capabilities;
        drop(provider_activation);
        drop(_secret_broker);
        drop(store);
        drop(bootstrap);

        combine_shutdown_results(http_result, runtime_result)
    }
}

pub(super) fn map_recovery_state(state: RecoveryState) -> HttpRecoveryState {
    match state {
        RecoveryState::Ready => HttpRecoveryState::Ready,
        RecoveryState::RecoveryBlocked => HttpRecoveryState::RecoveryBlocked,
        RecoveryState::IntegrityBlocked => HttpRecoveryState::IntegrityBlocked,
    }
}

async fn shutdown_runtime(
    controller: &mut RuntimeController,
    timeout: Duration,
) -> Result<(), DaemonError> {
    let outcome = tokio::time::timeout(
        timeout,
        controller.shutdown(ShutdownMode::Graceful { timeout }),
    )
    .await
    .map_err(|_| DaemonError::Bootstrap("runtime shutdown timeout".to_owned()))?;

    match outcome {
        ShutdownOutcome::Quiesced => {}
        ShutdownOutcome::Incomplete {
            active_workers,
            active_blocking_ops,
            rejected_commands,
        } => {
            return Err(DaemonError::Bootstrap(format!(
                "runtime shutdown incomplete: active_workers={active_workers}, \
                 active_blocking_ops={active_blocking_ops}, \
                 rejected_commands={rejected_commands}"
            )));
        }
    }

    let terminated = tokio::time::timeout(timeout, controller.wait_terminated())
        .await
        .map_err(|_| DaemonError::Bootstrap("runtime termination timeout".to_owned()))?;
    match terminated {
        ShutdownOutcome::Quiesced => Ok(()),
        ShutdownOutcome::Incomplete { .. } => Err(DaemonError::Bootstrap(
            "runtime termination was not quiescent".to_owned(),
        )),
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn combine_shutdown_results(
    http_result: Result<(), DaemonError>,
    runtime_result: Result<(), DaemonError>,
) -> Result<(), DaemonError> {
    match (http_result, runtime_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(http_error), Err(runtime_error)) => Err(DaemonError::Bootstrap(format!(
            "HTTP shutdown failed: {http_error}; runtime shutdown failed: {runtime_error}"
        ))),
    }
}
