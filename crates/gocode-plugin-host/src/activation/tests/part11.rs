    #[test]
    fn activation_history_always_ends_in_snapshot_state() {
        let stale_generation = request().activate_with_reservation(
            &mut Process::default(),
            &mut Transport::new(vec![]),
            &Generation::at(PluginGeneration::new(2).unwrap()),
            &Starts,
        );
        let start_intent_unavailable = request().activate_with_reservation(
            &mut Process::default(),
            &mut Transport::new(vec![]),
            &Generation::current(),
            &UnavailableStarts,
        );
        let backend_unavailable = request().activate_with_reservation(
            &mut UnavailableProcess::default(),
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        let rejected = request().activate_with_reservation(
            &mut RejectedProcess::default(),
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        let response_lost = request().activate_with_reservation(
            &mut LostResponseProcess::default(),
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        let negotiation_failed = request().activate_with_reservation(
            &mut Process::default(),
            &mut Transport::oversized(),
            &Generation::current(),
            &Starts,
        );
        let ready_cas_failed_request = request();
        let ready_cas_failed_profile = ready_cas_failed_request.protocol_profile();
        let ready_cas_failed = ready_cas_failed_request.activate_with_reservation(
            &mut Process::default(),
            &mut Transport::new(vec![
                hello(&ready_cas_failed_request, ready_cas_failed_profile.clone()),
                ack(&ready_cas_failed_request, ready_cas_failed_profile),
            ]),
            &Generation {
                fail_ready: true,
                generation: PluginGeneration::INITIAL,
            },
            &Starts,
        );
        let active = active_snapshot(
            PluginActivationId::new("history-active").unwrap(),
            PluginDigest::from_bytes([1; 32]),
            PluginGeneration::INITIAL,
        );
        let draining = active_snapshot(
            PluginActivationId::new("history-draining").unwrap(),
            PluginDigest::from_bytes([1; 32]),
            PluginGeneration::INITIAL,
        )
        .begin_draining()
        .unwrap();
        let terminal_active = active_snapshot(
            PluginActivationId::new("history-terminal").unwrap(),
            PluginDigest::from_bytes([1; 32]),
            PluginGeneration::INITIAL,
        );
        let terminal_evidence = PluginTerminalEvidence::certified(&terminal_active);
        let terminal = terminal_active
            .begin_draining()
            .unwrap()
            .terminal(terminal_evidence)
            .unwrap();
        let uncertain = active_snapshot(
            PluginActivationId::new("history-uncertain").unwrap(),
            PluginDigest::from_bytes([1; 32]),
            PluginGeneration::INITIAL,
        )
        .begin_draining()
        .unwrap()
        .uncertain()
        .unwrap();

        for snapshot in [
            stale_generation,
            start_intent_unavailable,
            backend_unavailable,
            rejected,
            response_lost,
            negotiation_failed,
            ready_cas_failed,
            active,
            draining,
            terminal,
            uncertain,
        ] {
            assert_eq!(
                snapshot.transition_history().last(),
                Some(&snapshot.state())
            );
        }
    }

    #[test]
    fn proven_backend_unavailability_reaches_start_and_remains_not_started() {
        let mut process = UnavailableProcess::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Verified);
        assert_eq!(process.calls, 1);
        assert_eq!(snapshot.transition_history(), [ActivationState::Verified]);
        assert_eq!(
            snapshot.attempt_receipts(),
            [
                PluginActivationReceipt::StartAttempted,
                PluginActivationReceipt::StartProvenNotStarted,
            ]
        );
        assert!(snapshot.start_intent.is_none());
        assert!(snapshot.generation_lease.is_none());
    }

    #[test]
    fn rejected_start_remains_verified_with_proven_not_started_receipt() {
        let mut process = RejectedProcess::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Verified);
        assert_eq!(process.calls, 1);
        assert_eq!(snapshot.transition_history(), [ActivationState::Verified]);
        assert_eq!(
            snapshot.attempt_receipts(),
            [
                PluginActivationReceipt::StartAttempted,
                PluginActivationReceipt::StartProvenNotStarted,
            ]
        );
    }

    #[test]
    fn lost_start_response_retains_start_intent_and_generation_lease_for_reconciliation() {
        let mut process = LostResponseProcess::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Uncertain);
        assert_eq!(process.calls, 1);
        assert_eq!(
            snapshot.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Uncertain,
            ]
        );
        assert!(snapshot.start_intent.is_some());
        assert!(snapshot.generation_lease.is_some());
        assert!(snapshot.process_lease.is_none());
    }

    #[test]
    fn exact_replay_reconciles_running_process_without_duplicate_start() {
        let request = request();
        let mut process = ReconciledProcess::started();
        let mut transport = exact_v2_transport(&request);
        let snapshot = request.activate_with_reservation(
            &mut process,
            &mut transport,
            &Generation::current(),
            &ExistingStarts,
        );

        assert_eq!(snapshot.state(), ActivationState::Active);
        assert_eq!(process.reconcile_calls, 1);
        assert_eq!(process.start_calls, 0);
        assert_eq!(
            snapshot.attempt_receipts(),
            [PluginActivationReceipt::ReconciliationAttempted]
        );
    }

    #[test]
    fn unavailable_existing_reconciliation_retains_intent_without_start_or_no_start_claim() {
        let mut process = UnavailableReconcileProcess::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &ExistingStarts,
        );

        assert_eq!(snapshot.state(), ActivationState::Uncertain);
        assert_eq!(process.reconcile_calls, 1);
        assert_eq!(process.start_calls, 0);
        assert_eq!(
            snapshot.attempt_receipts(),
            [PluginActivationReceipt::ReconciliationAttempted]
        );
        assert!(snapshot.start_intent.is_some());
        assert!(snapshot.generation_lease.is_some());
    }

    #[test]
    fn uncertain_start_can_be_reconciled_to_proven_not_started_without_retry() {
        let mut process = LostResponseProcess::default();
        let uncertain = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        let mut reconciliation = ReconciledProcess::not_started();

        let verified = uncertain.reconcile_process(&mut reconciliation).unwrap();

        assert_eq!(verified.state(), ActivationState::Verified);
        assert_eq!(reconciliation.reconcile_calls, 1);
        assert_eq!(reconciliation.start_calls, 0);
        assert_eq!(
            verified.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Uncertain,
                ActivationState::Verified,
            ]
        );
        assert_eq!(
            verified.attempt_receipts(),
            [
                PluginActivationReceipt::StartAttempted,
                PluginActivationReceipt::ReconciliationAttempted,
                PluginActivationReceipt::StartProvenNotStarted,
            ]
        );
    }

    #[test]
    fn mismatched_start_reservation_is_uncertain_after_process_boundary() {
        let request = request();
        let mut process = WrongReservationProcess::default();
        let snapshot = request.activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Uncertain);
        assert_eq!(process.calls, 1);
        assert!(snapshot.start_intent.is_some());
        assert!(snapshot.generation_lease.is_some());
        assert!(snapshot.process_lease.is_none());
    }
