impl OwnedRuntimeLifecycle for BundledRuntimeController {
    fn connect_runtime(&self) -> RuntimeConnectionFuture<'_> {
        Box::pin(self.connect())
    }

    fn stop_on_explicit_quit(&self) {
        if !self.operation_fence.begin_shutdown() {
            return;
        }
        let _operation = self.operation_fence.wait_for_idle();
        let core_fenced =
            tauri::async_runtime::block_on(self.core.fence_bundled_runtime_shutdown()).is_ok();
        let _ = self.clear_renewal_schedule();
        let stop_outcome = self
            .supervisor
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::ShutdownIncomplete)
            .and_then(|mut supervisor| supervisor.stop())
            .map_or(
                BundledShutdownOutcome::Incomplete,
                |disposition| match disposition {
                    BundledRuntimeStopDisposition::Graceful => BundledShutdownOutcome::Graceful,
                    BundledRuntimeStopDisposition::Forced => BundledShutdownOutcome::Forced,
                },
            );
        let outcome = if core_fenced {
            stop_outcome
        } else {
            BundledShutdownOutcome::Incomplete
        };
        if let Ok(mut recorded) = self.shutdown_outcome.lock() {
            *recorded = Some(outcome);
        }
    }
}

const fn map_protected_failure(error: ProtectedBundledRuntimeError) -> RuntimeFailureCode {
    match error {
        ProtectedBundledRuntimeError::UnsupportedPlatformBackend => {
            RuntimeFailureCode::UnsupportedPlatformBackend
        }
        ProtectedBundledRuntimeError::ExecutableUnavailable => {
            RuntimeFailureCode::BundledExecutableUnavailable
        }
        ProtectedBundledRuntimeError::ExecutableIdentityMismatch => {
            RuntimeFailureCode::BundledExecutableIdentityMismatch
        }
        ProtectedBundledRuntimeError::ReadinessTimeout
        | ProtectedBundledRuntimeError::OwnershipMismatch => {
            RuntimeFailureCode::ProtectedReadinessRejected
        }
        ProtectedBundledRuntimeError::RestartExhausted => {
            RuntimeFailureCode::BundledRestartExhausted
        }
        ProtectedBundledRuntimeError::ShutdownIncomplete => {
            RuntimeFailureCode::BundledShutdownIncomplete
        }
        ProtectedBundledRuntimeError::RuntimeRootUnavailable
        | ProtectedBundledRuntimeError::ActivationStateUnavailable
        | ProtectedBundledRuntimeError::ProtectedChannelUnavailable
        | ProtectedBundledRuntimeError::SpawnFailed
        | ProtectedBundledRuntimeError::InvalidState
        | ProtectedBundledRuntimeError::LaunchAuthority(_) => {
            RuntimeFailureCode::ProtectedActivationUnavailable
        }
    }
}
