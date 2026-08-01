fn map_recovery_state(state: RecoveryState) -> HttpRecoveryState {
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
