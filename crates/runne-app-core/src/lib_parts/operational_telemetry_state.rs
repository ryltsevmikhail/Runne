impl AppCore {
    /// Records a host lifecycle transition and emits a lifecycle event.
    ///
    /// # Errors
    ///
    /// Returns [`AppCoreError::StateUnavailable`] when the lifecycle state
    /// cannot be locked or the transition violates the runtime mode invariants.
    pub fn record_host_lifecycle(
        &self,
        lifecycle: RuntimeLifecycleStatus,
        failure: Option<RuntimeFailureCode>,
        generation: Option<u64>,
        observed_at_unix_seconds: u64,
    ) -> Result<(), AppCoreError> {
        self.record_host_lifecycle_inner(
            lifecycle,
            failure,
            generation,
            observed_at_unix_seconds,
            true,
        )
    }

    fn record_host_lifecycle_inner(
        &self,
        lifecycle: RuntimeLifecycleStatus,
        failure: Option<RuntimeFailureCode>,
        generation: Option<u64>,
        observed_at_unix_seconds: u64,
        restart_episode: bool,
    ) -> Result<(), AppCoreError> {
        let mut state = self
            .host_lifecycle
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let event = {
            HostLifecycleState::validate(lifecycle, failure, generation, self.runtime_mode)?;
            if !state.tuple_changed(lifecycle, failure, generation) {
                return Ok(());
            }
            if state.event_pipeline_unavailable {
                state.current = Some(HostLifecycleCurrentV1 {
                    lifecycle,
                    failure,
                    restart_ordinal: state.restart_ordinal,
                    runtime_launch_generation: generation,
                    observed_at_unix_seconds,
                });
                return Ok(());
            }
            let restart_ordinal = if restart_episode {
                if let Ok(ordinal) = state.next_restart_ordinal(lifecycle) {
                    ordinal
                } else {
                    state.current = Some(HostLifecycleCurrentV1 {
                        lifecycle,
                        failure,
                        restart_ordinal: state.restart_ordinal,
                        runtime_launch_generation: generation,
                        observed_at_unix_seconds,
                    });
                    state.event_pipeline_unavailable = true;
                    return Ok(());
                }
            } else {
                state.restart_ordinal
            };
            state.current = Some(HostLifecycleCurrentV1 {
                lifecycle,
                failure,
                restart_ordinal,
                runtime_launch_generation: generation,
                observed_at_unix_seconds,
            });
            state.allocate_sequence().map_or_else(
                |_| {
                    state.event_pipeline_unavailable = true;
                    None
                },
                |sequence| {
                    Some(HostLifecycleEventV1 {
                        sequence,
                        lifecycle,
                        failure,
                        restart_ordinal,
                        runtime_launch_generation: generation,
                        observed_at_unix_seconds,
                    })
                },
            )
        };
        if let Some(event) = event {
            self.record_lifecycle_send_failure(&self.lifecycle_sender.try_send(event));
        }
        drop(state);
        Ok(())
    }

    fn record_automatic_host_lifecycle(
        &self,
        lifecycle: RuntimeLifecycleStatus,
        failure: Option<RuntimeFailureCode>,
    ) -> Result<(), AppCoreError> {
        self.record_host_lifecycle(
            lifecycle,
            failure,
            self.automatic_generation(lifecycle)?,
            current_unix_seconds(),
        )
    }

    fn record_automatic_host_failure(
        &self,
        failure: Option<RuntimeFailureCode>,
    ) -> Result<(), AppCoreError> {
        let state = self
            .host_lifecycle
            .read()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let current = state.current().ok_or(AppCoreError::StateUnavailable)?;
        let lifecycle = current.lifecycle();
        let generation = current.runtime_launch_generation();
        drop(state);
        self.record_host_lifecycle(lifecycle, failure, generation, current_unix_seconds())
    }

    fn record_bundled_shutdown_lifecycle(&self) -> Result<(), AppCoreError> {
        let state = self
            .host_lifecycle
            .read()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let generation = state
            .current()
            .and_then(HostLifecycleCurrentV1::runtime_launch_generation);
        drop(state);
        self.record_host_lifecycle_inner(
            RuntimeLifecycleStatus::Restarting,
            None,
            generation,
            current_unix_seconds(),
            false,
        )
    }

    fn automatic_generation(
        &self,
        lifecycle: RuntimeLifecycleStatus,
    ) -> Result<Option<u64>, AppCoreError> {
        if self.runtime_mode == RuntimeMode::ExternalLocal {
            return Ok(None);
        }
        let state = self
            .host_lifecycle
            .read()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let current = state
            .current()
            .cloned()
            .ok_or(AppCoreError::StateUnavailable)?;
        drop(state);
        let generation = if lifecycle == RuntimeLifecycleStatus::Ready {
            self.runtime_client
                .read()
                .ok()
                .and_then(|client| {
                    client
                        .as_ref()
                        .map(|client| client.session_info().launch_generation)
                })
                .or_else(|| current.runtime_launch_generation())
        } else if lifecycle == RuntimeLifecycleStatus::Restarting
            && current.lifecycle() != RuntimeLifecycleStatus::Restarting
        {
            current
                .runtime_launch_generation()
                .and_then(|value| value.checked_add(1))
                .or_else(|| current.runtime_launch_generation())
        } else {
            current.runtime_launch_generation()
        };
        Ok(generation)
    }

    fn record_lifecycle_send_failure(
        &self,
        result: &Result<(), tokio::sync::mpsc::error::TrySendError<HostLifecycleEventV1>>,
    ) {
        match result {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                increment_counter(
                    &self.lifecycle_producer_drops,
                    &self.lifecycle_producer_drop_saturated,
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                increment_counter(
                    &self.lifecycle_producer_drops,
                    &self.lifecycle_producer_drop_saturated,
                );
                self.lifecycle_pipeline_closed.store(true, Ordering::Release);
            }
        }
    }
}
