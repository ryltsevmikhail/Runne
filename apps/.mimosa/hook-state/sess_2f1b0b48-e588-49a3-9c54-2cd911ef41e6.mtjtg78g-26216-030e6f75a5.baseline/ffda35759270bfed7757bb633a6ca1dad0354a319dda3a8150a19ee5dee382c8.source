impl BundledRuntimeController {
    async fn monitor_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(SUPERVISOR_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if self.operation_fence.is_stopping() {
                break;
            }
            self.monitor_once().await;
        }
    }

    async fn monitor_once(&self) {
        let Some(_operation) = self.operation_fence.enter().await else {
            return;
        };
        let Ok(before) = self.supervisor_state() else {
            let _ = self
                .core
                .mark_bundled_runtime_failed(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await;
            return;
        };
        let monitor_result = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::monitor)
            .await;
        let Ok(after) = self.supervisor_state() else {
            let _ = self
                .core
                .mark_bundled_runtime_failed(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await;
            return;
        };

        if let Err(error) = monitor_result {
            let failure = map_protected_failure(error);
            if after == BundledRuntimeLifecycleState::Exhausted {
                let _ = self.core.mark_bundled_runtime_failed(failure).await;
            } else {
                let _ = self.core.mark_bundled_runtime_degraded(failure).await;
            }
            return;
        }

        match (before, after) {
            (BundledRuntimeLifecycleState::Ready, BundledRuntimeLifecycleState::Ready)
                if self.renewal_is_due().unwrap_or(true) =>
            {
                self.rotate_protected_session().await;
            }
            (
                BundledRuntimeLifecycleState::Ready | BundledRuntimeLifecycleState::Handshaking,
                BundledRuntimeLifecycleState::Backoff,
            ) => {
                let _ = self.clear_renewal_schedule();
                let _ = self.core.begin_bundled_runtime_restart().await;
            }
            (BundledRuntimeLifecycleState::Backoff, BundledRuntimeLifecycleState::Handshaking) => {
                let Ok(lease) = self.core.begin_bundled_runtime_restart().await else {
                    return;
                };
                let _ = self.connect_pending_profile(lease).await;
            }
            (_, BundledRuntimeLifecycleState::Exhausted) => {
                let _ = self
                    .core
                    .mark_bundled_runtime_failed(RuntimeFailureCode::BundledRestartExhausted)
                    .await;
            }
            _ => {}
        }
    }

    async fn rotate_protected_session(&self) {
        self.clear_renewal_schedule().ok();
        let Ok(lease) = self.core.begin_bundled_runtime_restart().await else {
            return;
        };
        if let Err(error) = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::queue_renewal_profile)
            .await
        {
            let _ = self
                .reject_current_client(map_protected_failure(error))
                .await;
            return;
        }
        let _ = self.connect_pending_profile(lease).await;
    }

    fn arm_renewal_schedule(&self) -> Result<(), AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|mut schedule| schedule.arm(Instant::now()))
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn clear_renewal_schedule(&self) -> Result<(), AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|mut schedule| schedule.clear())
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn renewal_is_due(&self) -> Result<bool, AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|schedule| schedule.is_due(Instant::now()))
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn supervisor_state(&self) -> Result<BundledRuntimeLifecycleState, AppCoreError> {
        self.supervisor
            .lock()
            .map(|supervisor| supervisor.state())
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    async fn run_supervisor<T, F>(&self, action: F) -> Result<T, ProtectedBundledRuntimeError>
    where
        T: Send + 'static,
        F: FnOnce(
                &mut ProtectedBundledRuntimeSupervisor,
            ) -> Result<T, ProtectedBundledRuntimeError>
            + Send
            + 'static,
    {
        let supervisor = Arc::clone(&self.supervisor);
        tokio::task::spawn_blocking(move || {
            let mut supervisor = supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            action(&mut supervisor)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
    }

}
