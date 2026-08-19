    #[derive(Default)]
    struct Process {
        calls: usize,
    }
    impl PluginProcessPort for Process {
        fn start(
            &mut self,
            intent: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            Ok(PluginProcessLease::certified(intent))
        }
    }
    #[derive(Default)]
    struct UnavailableProcess {
        calls: usize,
    }
    impl PluginProcessPort for UnavailableProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            Err(PluginProcessPortError::BackendUnavailable)
        }
    }
    #[derive(Default)]
    struct LostResponseProcess {
        calls: usize,
    }
    #[derive(Default)]
    struct RejectedProcess {
        calls: usize,
    }
    impl PluginProcessPort for RejectedProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            Err(PluginProcessPortError::Rejected)
        }
    }
    impl PluginProcessPort for LostResponseProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            Err(PluginProcessPortError::ResponseLost)
        }
    }
    #[derive(Default)]
    struct WrongReservationProcess {
        calls: usize,
    }
    impl PluginProcessPort for WrongReservationProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            let wrong = PluginStartIntent::issued(
                PluginActivationId::new("wrong-reservation").unwrap(),
                PluginDigest::from_bytes([7; 32]),
                PluginGeneration::INITIAL,
                [9; 32],
            );
            Ok(PluginProcessLease::certified(&wrong))
        }
    }
    struct Generation {
        fail_ready: bool,
        generation: PluginGeneration,
    }
    /// Test-only stand-in for a durable authority. Its fixed epoch is part of
    /// the fixture identity, so a reconstructed fixture with another epoch
    /// cannot recreate a reservation accepted by an earlier one.
    struct Starts;
    impl PluginStartIntentPort for Starts {
        fn reserve(
            &self,
            activation_id: &PluginActivationId,
            package_digest: PluginDigest,
            generation: PluginGeneration,
        ) -> Result<PluginStartIntent, crate::PluginStartIntentPortError> {
            let mut reservation = [0; 32];
            reservation[..8].copy_from_slice(&generation.get().to_be_bytes());
            reservation[8..].copy_from_slice(&package_digest.as_bytes()[..24]);
            Ok(PluginStartIntent::issued(
                activation_id.clone(),
                package_digest,
                generation,
                reservation,
            ))
        }
    }
    struct UnavailableStarts;
    impl PluginStartIntentPort for UnavailableStarts {
        fn reserve(
            &self,
            _: &PluginActivationId,
            _: PluginDigest,
            _: PluginGeneration,
        ) -> Result<PluginStartIntent, crate::PluginStartIntentPortError> {
            Err(crate::PluginStartIntentPortError::Unavailable)
        }
    }
    struct ExistingStarts;
    impl PluginStartIntentPort for ExistingStarts {
        fn reserve(
            &self,
            activation_id: &PluginActivationId,
            package_digest: PluginDigest,
            generation: PluginGeneration,
        ) -> Result<PluginStartIntent, crate::PluginStartIntentPortError> {
            let mut reservation = [0; 32];
            reservation[..8].copy_from_slice(&generation.get().to_be_bytes());
            reservation[8..].copy_from_slice(&package_digest.as_bytes()[..24]);
            Ok(PluginStartIntent::with_origin(
                activation_id.clone(),
                package_digest,
                generation,
                reservation,
                PluginStartIntentOrigin::Existing,
            ))
        }
    }

    struct ReconciledProcess {
        reconcile_calls: usize,
        start_calls: usize,
        started: bool,
    }

    #[derive(Default)]
    struct UnavailableReconcileProcess {
        reconcile_calls: usize,
        start_calls: usize,
    }

    impl PluginProcessPort for UnavailableReconcileProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.start_calls += 1;
            Err(PluginProcessPortError::BackendUnavailable)
        }

        fn reconcile(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginStartReconciliation, PluginProcessPortError> {
            self.reconcile_calls += 1;
            Err(PluginProcessPortError::BackendUnavailable)
        }
    }

    impl ReconciledProcess {
        fn started() -> Self {
            Self {
                reconcile_calls: 0,
                start_calls: 0,
                started: true,
            }
        }

        fn not_started() -> Self {
            Self {
                reconcile_calls: 0,
                start_calls: 0,
                started: false,
            }
        }
    }

    impl PluginProcessPort for ReconciledProcess {
        fn start(
            &mut self,
            intent: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.start_calls += 1;
            Ok(PluginProcessLease::certified(intent))
        }

        fn reconcile(
            &mut self,
            intent: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginStartReconciliation, PluginProcessPortError> {
            self.reconcile_calls += 1;
            if self.started {
                Ok(PluginStartReconciliation::Started(
                    PluginProcessLease::certified(intent),
                ))
            } else {
                Ok(PluginStartReconciliation::NotStarted)
            }
        }
    }
    impl Generation {
        fn current() -> Self {
            Self::at(PluginGeneration::INITIAL)
        }
        fn at(generation: PluginGeneration) -> Self {
            Self {
                fail_ready: false,
                generation,
            }
        }
    }
    impl PluginGenerationPort for Generation {
        fn acquire_read_lease(
            &self,
            id: &PluginActivationId,
        ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
            Ok(PluginGenerationReadLease::issued(
                id.clone(),
                self.generation,
            ))
        }
        fn ready_compare_and_set(
            &self,
            _: &PluginGenerationReadLease,
        ) -> Result<(), PluginGenerationPortError> {
            if self.fail_ready {
                Err(PluginGenerationPortError::Unavailable)
            } else {
                Ok(())
            }
        }
    }
