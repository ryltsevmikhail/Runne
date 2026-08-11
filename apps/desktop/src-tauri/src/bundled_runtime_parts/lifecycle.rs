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

impl NativeRootAdmissionLifecycle for BundledRuntimeController {
    fn prepare_root_admission(
        &self,
        root: gocode_platform_desktop::VerifiedRootHandle,
        workspace_id: gocode_platform_desktop::WorkspaceId,
        expected_version: u64,
    ) -> RootAdmissionFuture {
        let supervisor = Arc::clone(&self.supervisor);
        let fence = Arc::clone(&self.operation_fence);
        Box::pin(async move {
            let Some(operation_permit) = fence.enter().await else {
                return Err(AppCoreError::RuntimeUnavailable);
            };
            tauri::async_runtime::spawn_blocking(move || {
                let admission = supervisor
                    .lock()
                    .map_err(|_| AppCoreError::RuntimeUnavailable)?
                    .prepare_root_admission(&root, workspace_id, expected_version)
                    .map_err(|_| AppCoreError::RuntimeUnavailable)?;
                Ok(NativeRootAdmission { root, admission, operation_permit })
            })
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
        })
    }

    fn reap_failed_root_admission(
        &self,
        operation_permit: tokio::sync::OwnedMutexGuard<()>,
    ) -> RootAdmissionReapFuture {
        let supervisor = Arc::clone(&self.supervisor);
        Box::pin(async move {
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let _operation = operation_permit;
                let _ = supervisor.lock().map(|mut value| value.stop());
            })
            .await;
        })
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
