    #[derive(Default)]
    struct CertifiedLifecycleProcess {
        drain_calls: usize,
        terminal_calls: usize,
        cleanup_calls: usize,
    }

    #[derive(Default)]
    struct LostDrainThenSuccess {
        drain_calls: usize,
    }

    struct MismatchedDrain {
        evidence: Option<PluginDrainEvidence>,
    }

    impl PluginProcessPort for MismatchedDrain {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            Err(PluginProcessPortError::BackendUnavailable)
        }

        fn begin_draining(
            &mut self,
            _: &PluginProcessLease,
        ) -> Result<PluginDrainEvidence, PluginProcessPortError> {
            Ok(self.evidence.take().unwrap())
        }
    }

    impl PluginProcessPort for LostDrainThenSuccess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            Err(PluginProcessPortError::BackendUnavailable)
        }

        fn begin_draining(
            &mut self,
            lease: &PluginProcessLease,
        ) -> Result<PluginDrainEvidence, PluginProcessPortError> {
            self.drain_calls += 1;
            if self.drain_calls == 1 {
                Err(PluginProcessPortError::ResponseLost)
            } else {
                Ok(PluginDrainEvidence::certified(lease))
            }
        }
    }

    #[derive(Default)]
    struct LostCleanupThenSuccess {
        terminal_calls: usize,
        cleanup_calls: usize,
    }

    struct MismatchedCleanupThenSuccess {
        terminal_calls: usize,
        cleanup_calls: usize,
        mismatched: Option<PluginCleanupEvidence>,
    }

    impl PluginProcessPort for MismatchedCleanupThenSuccess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            Err(PluginProcessPortError::BackendUnavailable)
        }

        fn begin_draining(
            &mut self,
            lease: &PluginProcessLease,
        ) -> Result<PluginDrainEvidence, PluginProcessPortError> {
            Ok(PluginDrainEvidence::certified(lease))
        }

        fn terminal(
            &mut self,
            lease: &PluginProcessLease,
            _: &PluginDrainEvidence,
        ) -> Result<PluginTerminalEvidence, PluginProcessPortError> {
            self.terminal_calls += 1;
            Ok(PluginTerminalEvidence::certified_process(lease))
        }

        fn cleanup(
            &mut self,
            lease: &PluginProcessLease,
            _: &PluginTerminalEvidence,
        ) -> Result<PluginCleanupEvidence, PluginProcessPortError> {
            self.cleanup_calls += 1;
            Ok(self
                .mismatched
                .take()
                .unwrap_or_else(|| PluginCleanupEvidence::certified(lease)))
        }
    }

    impl PluginProcessPort for LostCleanupThenSuccess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            Err(PluginProcessPortError::BackendUnavailable)
        }

        fn begin_draining(
            &mut self,
            lease: &PluginProcessLease,
        ) -> Result<PluginDrainEvidence, PluginProcessPortError> {
            Ok(PluginDrainEvidence::certified(lease))
        }

        fn terminal(
            &mut self,
            lease: &PluginProcessLease,
            _: &PluginDrainEvidence,
        ) -> Result<PluginTerminalEvidence, PluginProcessPortError> {
            self.terminal_calls += 1;
            Ok(PluginTerminalEvidence::certified_process(lease))
        }

        fn cleanup(
            &mut self,
            lease: &PluginProcessLease,
            _: &PluginTerminalEvidence,
        ) -> Result<PluginCleanupEvidence, PluginProcessPortError> {
            self.cleanup_calls += 1;
            if self.cleanup_calls == 1 {
                Err(PluginProcessPortError::ResponseLost)
            } else {
                Ok(PluginCleanupEvidence::certified(lease))
            }
        }
    }

    impl PluginProcessPort for CertifiedLifecycleProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            Err(PluginProcessPortError::BackendUnavailable)
        }

        fn begin_draining(
            &mut self,
            lease: &PluginProcessLease,
        ) -> Result<PluginDrainEvidence, PluginProcessPortError> {
            self.drain_calls += 1;
            Ok(PluginDrainEvidence::certified(lease))
        }

        fn terminal(
            &mut self,
            lease: &PluginProcessLease,
            drain: &PluginDrainEvidence,
        ) -> Result<PluginTerminalEvidence, PluginProcessPortError> {
            self.terminal_calls += 1;
            if !drain.matches(lease) {
                return Err(PluginProcessPortError::Rejected);
            }
            Ok(PluginTerminalEvidence::certified_process(lease))
        }

        fn cleanup(
            &mut self,
            lease: &PluginProcessLease,
            terminal: &PluginTerminalEvidence,
        ) -> Result<PluginCleanupEvidence, PluginProcessPortError> {
            self.cleanup_calls += 1;
            let snapshot = active_snapshot(
                lease.activation_id().clone(),
                lease.package_digest(),
                lease.generation(),
            );
            if !terminal.matches(&snapshot) {
                return Err(PluginProcessPortError::Rejected);
            }
            Ok(PluginCleanupEvidence::certified(lease))
        }
    }
