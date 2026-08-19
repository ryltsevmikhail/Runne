impl PluginActivationSnapshot {
    /// Consumes Active only after the process backend certifies the drain boundary.
    pub fn begin_draining_with_backend(
        mut self,
        process: &mut dyn PluginProcessPort,
    ) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if !matches!(
            self.state,
            ActivationState::Active | ActivationState::Uncertain
        ) || self.drain_evidence.is_some()
            || self.terminal_evidence.is_some()
        {
            return Err(Box::new((self, PluginLifecycleError::InvalidTransition)));
        }
        let Some(process_lease) = self.process_lease.as_ref() else {
            return Err(Box::new((
                self,
                PluginLifecycleError::InvalidBackendEvidence,
            )));
        };
        let evidence = match process.begin_draining(process_lease) {
            Ok(evidence) if evidence.matches(process_lease) => evidence,
            Ok(_) => {
                self.state = ActivationState::Uncertain;
                self.active_fence = None;
                if self.history.last() != Some(&ActivationState::Uncertain) {
                    self.record(ActivationState::Uncertain);
                }
                return Ok(self);
            }
            Err(PluginProcessPortError::ResponseLost) => {
                self.state = ActivationState::Uncertain;
                self.active_fence = None;
                if self.history.last() != Some(&ActivationState::Uncertain) {
                    self.record(ActivationState::Uncertain);
                }
                return Ok(self);
            }
            Err(_) => return Err(Box::new((self, PluginLifecycleError::BackendUnavailable))),
        };
        self.state = ActivationState::Draining;
        self.drain_evidence = Some(evidence);
        self.active_fence = None;
        self.record(ActivationState::Draining);
        Ok(self)
    }

    /// Consumes Draining only after terminal and cleanup evidence are certified
    /// by the backend for the exact retained process lease.
    pub fn terminal_with_backend(
        mut self,
        process: &mut dyn PluginProcessPort,
    ) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if !matches!(
            self.state,
            ActivationState::Draining | ActivationState::Uncertain
        ) {
            return Err(Box::new((self, PluginLifecycleError::InvalidTransition)));
        }
        let (Some(process_lease), Some(drain_evidence)) =
            (self.process_lease.as_ref(), self.drain_evidence.as_ref())
        else {
            return Err(Box::new((
                self,
                PluginLifecycleError::InvalidBackendEvidence,
            )));
        };
        let terminal = match self.terminal_evidence.take() {
            Some(evidence) => evidence,
            None => match process.terminal(process_lease, drain_evidence) {
                Ok(evidence) if evidence.matches(&self) => evidence,
                Ok(_) => {
                    return Err(Box::new((
                        self,
                        PluginLifecycleError::InvalidTerminalEvidence,
                    )));
                }
                Err(PluginProcessPortError::ResponseLost) => {
                    self.state = ActivationState::Uncertain;
                    if self.history.last() != Some(&ActivationState::Uncertain) {
                        self.record(ActivationState::Uncertain);
                    }
                    return Ok(self);
                }
                Err(_) => {
                    return Err(Box::new((self, PluginLifecycleError::BackendUnavailable)));
                }
            },
        };
        let cleanup = match process.cleanup(process_lease, &terminal) {
            Ok(evidence) if evidence.matches(process_lease) => evidence,
            Ok(_) => {
                self.terminal_evidence = Some(terminal);
                self.state = ActivationState::Uncertain;
                if self.history.last() != Some(&ActivationState::Uncertain) {
                    self.record(ActivationState::Uncertain);
                }
                return Ok(self);
            }
            Err(_) => {
                self.terminal_evidence = Some(terminal);
                self.state = ActivationState::Uncertain;
                if self.history.last() != Some(&ActivationState::Uncertain) {
                    self.record(ActivationState::Uncertain);
                }
                return Ok(self);
            }
        };
        self.commit_terminal(terminal, cleanup)
    }

    /// Test-only in-memory helper; production lifecycle must call
    /// [`Self::begin_draining_with_backend`].
    #[cfg(test)]
    pub fn begin_draining(mut self) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if self.state != ActivationState::Active {
            return Err(Box::new((self, PluginLifecycleError::InvalidTransition)));
        }
        self.state = ActivationState::Draining;
        self.drain_evidence = self
            .process_lease
            .as_ref()
            .map(PluginDrainEvidence::certified);
        self.active_fence = None;
        self.record(ActivationState::Draining);
        Ok(self)
    }

    #[cfg(test)]
    pub fn terminal(
        self,
        evidence: PluginTerminalEvidence,
    ) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        let cleanup = match self.process_lease.as_ref() {
            Some(lease) => PluginCleanupEvidence::certified(lease),
            None => {
                return Err(Box::new((
                    self,
                    PluginLifecycleError::InvalidTerminalEvidence,
                )));
            }
        };
        self.commit_terminal(evidence, cleanup)
    }

    fn commit_terminal(
        mut self,
        evidence: PluginTerminalEvidence,
        cleanup: PluginCleanupEvidence,
    ) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if !matches!(
            self.state,
            ActivationState::Draining | ActivationState::Uncertain
        ) || !evidence.matches(&self)
        {
            return Err(Box::new((
                self,
                PluginLifecycleError::InvalidTerminalEvidence,
            )));
        }
        if !self
            .process_lease
            .as_ref()
            .is_some_and(|lease| cleanup.matches(lease))
        {
            return Err(Box::new((
                self,
                PluginLifecycleError::InvalidBackendEvidence,
            )));
        }
        self.state = ActivationState::Terminal;
        self.record(ActivationState::Terminal);
        self.process_lease = None;
        self.drain_evidence = None;
        self.terminal_evidence = None;
        self.generation_lease = None;
        self.active_fence = None;
        Ok(self)
    }

    /// Consumes Draining and retains the exact leases for reconciliation.
    pub fn uncertain(mut self) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if self.state != ActivationState::Draining {
            return Err(Box::new((self, PluginLifecycleError::InvalidTransition)));
        }
        self.state = ActivationState::Uncertain;
        self.record(ActivationState::Uncertain);
        Ok(self)
    }
}
