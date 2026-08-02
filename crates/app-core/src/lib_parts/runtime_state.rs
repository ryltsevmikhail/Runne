impl AppCore {
    fn require_bundled_mode(&self) -> Result<(), AppCoreError> {
        if self.runtime_mode == RuntimeMode::Bundled {
            Ok(())
        } else {
            Err(AppCoreError::RuntimeUnavailable)
        }
    }

    fn rotate_bundled_activation_lease(
        &self,
    ) -> Result<BundledRuntimeActivationLease, AppCoreError> {
        let mut epoch = self
            .bundled_activation_epoch
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let next = epoch.checked_add(1).ok_or(AppCoreError::StateUnavailable)?;
        *epoch = next;
        drop(epoch);
        Ok(BundledRuntimeActivationLease { epoch: next })
    }

    fn consume_bundled_activation_lease(
        &self,
        lease: BundledRuntimeActivationLease,
    ) -> Result<(), AppCoreError> {
        let mut epoch = self
            .bundled_activation_epoch
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        if *epoch != lease.epoch {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        *epoch = epoch.checked_add(1).ok_or(AppCoreError::StateUnavailable)?;
        drop(epoch);
        Ok(())
    }

    fn invalidate_bundled_activation_lease(&self) -> Result<(), AppCoreError> {
        self.rotate_bundled_activation_lease().map(|_| ())
    }

    fn runtime_availability(&self) -> Result<RuntimeAvailability, AppCoreError> {
        self.runtime_state
            .read()
            .map(|state| *state)
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn runtime_lifecycle(&self) -> Result<RuntimeLifecycleStatus, AppCoreError> {
        self.runtime_lifecycle
            .read()
            .map(|state| *state)
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn runtime_failure(&self) -> Result<Option<RuntimeFailureCode>, AppCoreError> {
        self.runtime_failure
            .read()
            .map(|failure| *failure)
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn set_runtime_lifecycle(&self, lifecycle: RuntimeLifecycleStatus) -> Result<(), AppCoreError> {
        *self
            .runtime_lifecycle
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = lifecycle;
        Ok(())
    }

    fn set_runtime_failure_code(
        &self,
        failure: Option<RuntimeFailureCode>,
    ) -> Result<(), AppCoreError> {
        *self
            .runtime_failure
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = failure;
        Ok(())
    }

    fn effective_runtime_availability(&self) -> Result<RuntimeAvailability, AppCoreError> {
        let raw = self.runtime_availability()?;
        let pending_resync = !self
            .pending_resync_scopes
            .read()
            .map_err(|_| AppCoreError::StateUnavailable)?
            .is_empty();
        if pending_resync
            && !matches!(
                raw,
                RuntimeAvailability::Fatal
                    | RuntimeAvailability::Incompatible
                    | RuntimeAvailability::Revoked
            )
        {
            Ok(RuntimeAvailability::ResyncRequired)
        } else {
            Ok(raw)
        }
    }

    fn set_runtime_availability(
        &self,
        availability: RuntimeAvailability,
    ) -> Result<(), AppCoreError> {
        *self
            .runtime_state
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = availability;
        Ok(())
    }

    fn transition_runtime(&self, availability: RuntimeAvailability) -> Result<(), AppCoreError> {
        let current = self.runtime_availability()?;
        let next = current
            .transition_to(availability)
            .map_err(|_| AppCoreError::StateUnavailable)?;
        self.set_runtime_availability(next)?;
        if self.runtime_mode == RuntimeMode::Bundled && next == RuntimeAvailability::Live {
            let lifecycle = if self.has_pending_resync()? {
                RuntimeLifecycleStatus::Degraded
            } else {
                RuntimeLifecycleStatus::Ready
            };
            self.set_runtime_lifecycle(lifecycle)?;
            self.set_runtime_failure_code(None)?;
        }
        Ok(())
    }

    fn set_runtime_failure(&self, availability: RuntimeAvailability) -> Result<(), AppCoreError> {
        self.set_runtime_availability(availability)?;
        if self.runtime_mode == RuntimeMode::Bundled {
            let lifecycle = match availability {
                RuntimeAvailability::Reconnecting | RuntimeAvailability::ResyncRequired => {
                    RuntimeLifecycleStatus::Degraded
                }
                RuntimeAvailability::Incompatible
                | RuntimeAvailability::Revoked
                | RuntimeAvailability::Fatal => RuntimeLifecycleStatus::Failed,
                _ => return Ok(()),
            };
            self.set_runtime_lifecycle(lifecycle)?;
        }
        Ok(())
    }

    fn set_resync_required_for_scope(&self, scope_key: ReplayScopeKey) -> Result<(), AppCoreError> {
        self.pending_resync_scopes
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)?
            .insert(scope_key);
        self.set_runtime_failure(RuntimeAvailability::ResyncRequired)
    }

    fn has_pending_resync(&self) -> Result<bool, AppCoreError> {
        self.pending_resync_scopes
            .read()
            .map(|scopes| !scopes.is_empty())
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn resync_required_for_scope(&self, scope_key: &ReplayScopeKey) -> Result<bool, AppCoreError> {
        self.pending_resync_scopes
            .read()
            .map(|scopes| scopes.contains(scope_key))
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn clear_resync_scope(&self, scope_key: &ReplayScopeKey) -> Result<(), AppCoreError> {
        self.pending_resync_scopes
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)?
            .remove(scope_key);
        Ok(())
    }

    fn runtime_client(&self) -> Result<Option<AuthenticatedRuntimeClient>, AppCoreError> {
        self.runtime_client
            .read()
            .map(|client| client.clone())
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn runtime_client_is_current(
        &self,
        expected: &AuthenticatedRuntimeClient,
    ) -> Result<bool, AppCoreError> {
        Ok(self.runtime_client()?.is_some_and(|current| {
            current.session_info().session_id == expected.session_info().session_id
                && current.session_info().daemon_instance_id
                    == expected.session_info().daemon_instance_id
                && current.session_info().launch_generation
                    == expected.session_info().launch_generation
        }))
    }

    fn live_runtime_client(&self) -> Result<AuthenticatedRuntimeClient, AppCoreError> {
        if !self.runtime_availability()?.allows_mutations() {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.runtime_client()?
            .ok_or(AppCoreError::RuntimeUnavailable)
    }
}
