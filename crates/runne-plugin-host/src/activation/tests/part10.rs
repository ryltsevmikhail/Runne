    #[test]
    fn lifecycle_uncertain_has_one_drain_and_no_terminal_call_with_retained_leases() {
        let active = active_snapshot(
            PluginActivationId::new("counted-uncertain").unwrap(),
            PluginDigest::from_bytes([6; 32]),
            PluginGeneration::INITIAL,
        );
        let mut lifecycle = CountingLifecycle::default();
        let uncertain = lifecycle.uncertain(active).unwrap();

        assert_eq!(lifecycle.drain_calls, 1);
        assert_eq!(lifecycle.terminal_calls, 0);
        assert_eq!(uncertain.state(), ActivationState::Uncertain);
        assert_eq!(
            uncertain.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
                ActivationState::Draining,
                ActivationState::Uncertain,
            ]
        );
        assert_eq!(
            uncertain.attempt_receipts(),
            [PluginActivationReceipt::StartAttempted]
        );
        assert!(uncertain.start_intent.is_some());
        assert!(uncertain.process_lease.is_some());
        assert!(uncertain.generation_lease.is_some());
    }

    #[test]
    fn lifecycle_invalid_evidence_then_retry_has_one_drain_and_two_terminal_calls() {
        let active = active_snapshot(
            PluginActivationId::new("counted-retry").unwrap(),
            PluginDigest::from_bytes([7; 32]),
            PluginGeneration::INITIAL,
        );
        let other = active_snapshot(
            PluginActivationId::new("counted-other").unwrap(),
            PluginDigest::from_bytes([7; 32]),
            PluginGeneration::INITIAL,
        );
        let mut lifecycle = CountingLifecycle::default();
        let draining = lifecycle.drain(active).unwrap();
        let valid = PluginTerminalEvidence::certified(&draining);
        let retained = lifecycle
            .terminal_with(draining, PluginTerminalEvidence::certified(&other))
            .unwrap_err();
        assert_eq!(lifecycle.drain_calls, 1);
        assert_eq!(lifecycle.terminal_calls, 1);
        assert_eq!(retained.state(), ActivationState::Draining);
        assert_eq!(
            retained.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
                ActivationState::Draining,
            ]
        );
        assert_eq!(
            retained.attempt_receipts(),
            [PluginActivationReceipt::StartAttempted]
        );
        assert!(retained.start_intent.is_some());
        assert!(retained.process_lease.is_some());
        assert!(retained.generation_lease.is_some());
        let terminal = lifecycle.terminal_with(*retained, valid).unwrap();

        assert_eq!(lifecycle.drain_calls, 1);
        assert_eq!(lifecycle.terminal_calls, 2);
        assert_eq!(terminal.state(), ActivationState::Terminal);
        assert_eq!(
            terminal.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
                ActivationState::Draining,
                ActivationState::Terminal,
            ]
        );
        assert_eq!(
            terminal.attempt_receipts(),
            [PluginActivationReceipt::StartAttempted]
        );
        assert_terminal_reconciliation_leases_cleared(&terminal);
    }

    fn assert_first_exchange_failure(request: PluginActivationRequest, response: BootstrapMessage) {
        let mut process = CountingProcess::success();
        let mut transport = CountingTransport::new(vec![WireResponse::V1(response)]);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_uncertain_after_first_exchange(&snapshot, &process, &transport, &generation);
    }

    fn assert_uncertain_after_first_exchange(
        snapshot: &PluginActivationSnapshot,
        process: &CountingProcess,
        transport: &CountingTransport,
        generation: &impl ReadyCasCounter,
    ) {
        assert_stage_case(
            snapshot,
            ActivationState::Uncertain,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Uncertain,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            process,
            transport,
            generation,
            (1, 1, 1, 0),
        );
    }

    #[allow(clippy::too_many_arguments)] // Matrix contract deliberately lists independent evidence dimensions.
    fn assert_stage_case(
        snapshot: &PluginActivationSnapshot,
        state: ActivationState,
        history: &[ActivationState],
        receipts: &[PluginActivationReceipt],
        retains_reconciliation_leases: bool,
        process: &CountingProcess,
        transport: &CountingTransport,
        generation: &impl ReadyCasCounter,
        counts: (usize, usize, usize, usize),
    ) {
        assert_eq!(snapshot.state(), state);
        assert_eq!(snapshot.transition_history(), history);
        assert_eq!(snapshot.attempt_receipts(), receipts);
        assert_eq!(
            snapshot.start_intent.is_some(),
            retains_reconciliation_leases
        );
        assert_eq!(
            snapshot.process_lease.is_some(),
            retains_reconciliation_leases
        );
        assert_eq!(
            snapshot.generation_lease.is_some(),
            retains_reconciliation_leases
        );
        assert_eq!(process.start_calls, counts.0);
        assert_eq!(transport.write_calls, counts.1);
        assert_eq!(transport.read_calls, counts.2);
        assert_eq!(generation.ready_cas_calls(), counts.3);
    }

    fn assert_no_reconciliation_leases(snapshot: &PluginActivationSnapshot) {
        assert!(snapshot.start_intent.is_none());
        assert!(snapshot.process_lease.is_none());
        assert!(snapshot.generation_lease.is_none());
    }

    fn assert_terminal_reconciliation_leases_cleared(snapshot: &PluginActivationSnapshot) {
        assert!(snapshot.start_intent.is_some());
        assert!(snapshot.process_lease.is_none());
        assert!(snapshot.generation_lease.is_none());
    }

    #[derive(Default)]
    struct CountingLifecycle {
        drain_calls: usize,
        terminal_calls: usize,
    }

    impl CountingLifecycle {
        fn drain(
            &mut self,
            snapshot: PluginActivationSnapshot,
        ) -> Result<PluginActivationSnapshot, Box<(PluginActivationSnapshot, PluginLifecycleError)>>
        {
            self.drain_calls += 1;
            snapshot.begin_draining()
        }

        fn terminal(
            &mut self,
            snapshot: PluginActivationSnapshot,
        ) -> Result<PluginActivationSnapshot, Box<(PluginActivationSnapshot, PluginLifecycleError)>>
        {
            let evidence = PluginTerminalEvidence::certified(&snapshot);
            let draining = self.drain(snapshot)?;
            self.terminal_calls += 1;
            draining.terminal(evidence)
        }

        fn uncertain(
            &mut self,
            snapshot: PluginActivationSnapshot,
        ) -> Result<PluginActivationSnapshot, Box<(PluginActivationSnapshot, PluginLifecycleError)>>
        {
            self.drain_calls += 1;
            snapshot.begin_draining()?.uncertain()
        }

        fn terminal_with(
            &mut self,
            snapshot: PluginActivationSnapshot,
            evidence: PluginTerminalEvidence,
        ) -> Result<PluginActivationSnapshot, Box<PluginActivationSnapshot>> {
            self.terminal_calls += 1;
            snapshot.terminal(evidence).map_err(|error| {
                let (snapshot, lifecycle_error) = *error;
                assert_eq!(
                    lifecycle_error,
                    PluginLifecycleError::InvalidTerminalEvidence
                );
                Box::new(snapshot)
            })
        }
    }
