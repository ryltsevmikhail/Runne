impl AppCore {
    /// Fences the previous bundled client and exposes a fresh initial
    /// activation attempt.
    ///
    /// # Errors
    ///
    /// Returns a closed error for external mode or poisoned application state.
    pub async fn begin_bundled_runtime_start(
        &self,
    ) -> Result<BundledRuntimeActivationLease, AppCoreError> {
        self.begin_bundled_runtime_connection(RuntimeLifecycleStatus::Starting)
            .await
    }

    /// Fences the previous bundled client before a generation/session rotation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for external mode or poisoned application state.
    pub async fn begin_bundled_runtime_restart(
        &self,
    ) -> Result<BundledRuntimeActivationLease, AppCoreError> {
        self.begin_bundled_runtime_connection(RuntimeLifecycleStatus::Restarting)
            .await
    }

    /// Fences the current bundled client and activation epoch for the native
    /// host's explicit-quit sequence. The host-level shutdown fence remains
    /// responsible for rejecting every later activation attempt.
    ///
    /// # Errors
    ///
    /// Returns a closed error for external mode or poisoned application state.
    pub async fn fence_bundled_runtime_shutdown(&self) -> Result<(), AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.require_bundled_mode()?;
        self.invalidate_bundled_activation_lease()?;
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = None;
        self.set_runtime_availability(RuntimeAvailability::Reconnecting)?;
        self.record_bundled_shutdown_lifecycle()?;
        self.set_runtime_failure_code(None)
    }

    async fn begin_bundled_runtime_connection(
        &self,
        lifecycle: RuntimeLifecycleStatus,
    ) -> Result<BundledRuntimeActivationLease, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.require_bundled_mode()?;
        let lease = self.rotate_bundled_activation_lease()?;
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = None;
        self.set_runtime_availability(RuntimeAvailability::Reconnecting)?;
        self.set_runtime_lifecycle(lifecycle)?;
        self.set_runtime_failure_code(None)?;
        Ok(lease)
    }

    /// Installs only a client authenticated through protected bundled
    /// activation. Credential-first external clients are rejected as a
    /// downgrade.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for the wrong mode, transport downgrade, or
    /// invalid state transition.
    pub async fn install_bundled_runtime_client(
        &self,
        lease: BundledRuntimeActivationLease,
        client: AuthenticatedRuntimeClient,
    ) -> Result<RuntimeAvailability, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.require_bundled_mode()?;
        self.consume_bundled_activation_lease(lease)?;
        if client.transport_kind() != RuntimeTransportKind::ProtectedBundled {
            *self
                .runtime_client
                .write()
                .map_err(|_| AppCoreError::StateUnavailable)? = None;
            self.set_runtime_availability(RuntimeAvailability::Incompatible)?;
            self.set_runtime_lifecycle(RuntimeLifecycleStatus::Failed)?;
            self.set_runtime_failure_code(Some(RuntimeFailureCode::DowngradedExternalProfile))?;
            return Err(AppCoreError::RuntimeUnavailable);
        }

        self.set_runtime_availability(RuntimeAvailability::Reconnecting)?;
        self.transition_runtime(RuntimeAvailability::ProfileLoaded)?;
        self.transition_runtime(RuntimeAvailability::PeerVerified)?;
        self.transition_runtime(RuntimeAvailability::BootstrapProved)?;
        self.transition_runtime(RuntimeAvailability::Authenticated)?;
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = Some(client);
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        self.transition_runtime(RuntimeAvailability::Live)?;
        self.set_runtime_failure_code(None)?;
        Ok(RuntimeAvailability::Live)
    }

    /// Marks a recoverable bundled runtime failure without exposing internal
    /// diagnostics.
    ///
    /// # Errors
    ///
    /// Returns a closed error for external mode or poisoned application state.
    pub async fn mark_bundled_runtime_degraded(
        &self,
        failure: RuntimeFailureCode,
    ) -> Result<(), AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.require_bundled_mode()?;
        self.invalidate_bundled_activation_lease()?;
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = None;
        self.set_runtime_availability(RuntimeAvailability::Reconnecting)?;
        self.set_runtime_lifecycle(RuntimeLifecycleStatus::Degraded)?;
        self.set_runtime_failure_code(Some(failure))
    }

    /// Marks a terminal bundled activation/supervision failure, or routes a
    /// missing authenticated configuration to its dedicated lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns a closed error for external mode or poisoned application state.
    pub async fn mark_bundled_runtime_failed(
        &self,
        failure: RuntimeFailureCode,
    ) -> Result<(), AppCoreError> {
        if failure == RuntimeFailureCode::ConfigurationRequired {
            return self.mark_bundled_runtime_configuration_required().await;
        }
        let _operation = self.runtime_operation.lock().await;
        self.require_bundled_mode()?;
        self.invalidate_bundled_activation_lease()?;
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = None;
        self.set_runtime_availability(RuntimeAvailability::Fatal)?;
        self.set_runtime_lifecycle(RuntimeLifecycleStatus::Failed)?;
        self.set_runtime_failure_code(Some(failure))
    }

    /// Records that bundled startup requires authenticated native enrollment.
    ///
    /// # Errors
    ///
    /// Returns a closed error for external mode or poisoned application state.
    pub async fn mark_bundled_runtime_configuration_required(&self) -> Result<(), AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.require_bundled_mode()?;
        self.invalidate_bundled_activation_lease()?;
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = None;
        self.set_runtime_availability(RuntimeAvailability::Unconfigured)?;
        self.set_runtime_lifecycle(RuntimeLifecycleStatus::ConfigurationRequired)?;
        self.set_runtime_failure_code(Some(RuntimeFailureCode::ConfigurationRequired))
    }
}
