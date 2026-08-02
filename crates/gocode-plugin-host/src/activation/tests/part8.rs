    #[test]
    fn lifecycle_terminal_has_one_drain_and_one_terminal_call_with_no_reconciliation_leases() {
        let active = active_snapshot(
            PluginActivationId::new("counted-terminal").unwrap(),
            PluginDigest::from_bytes([5; 32]),
            PluginGeneration::INITIAL,
        );
        let mut lifecycle = CountingLifecycle::default();
        let terminal = lifecycle.terminal(active).unwrap();

        assert_eq!(lifecycle.drain_calls, 1);
        assert_eq!(lifecycle.terminal_calls, 1);
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

    #[test]
    fn backend_lifecycle_commits_only_after_drain_terminal_and_cleanup_evidence() {
        let active = active_snapshot(
            PluginActivationId::new("backend-lifecycle").unwrap(),
            PluginDigest::from_bytes([4; 32]),
            PluginGeneration::INITIAL,
        );
        let mut backend = CertifiedLifecycleProcess::default();

        let draining = active.begin_draining_with_backend(&mut backend).unwrap();
        assert_eq!(draining.state(), ActivationState::Draining);
        assert_eq!(
            (
                backend.drain_calls,
                backend.terminal_calls,
                backend.cleanup_calls
            ),
            (1, 0, 0)
        );

        let terminal = draining.terminal_with_backend(&mut backend).unwrap();
        assert_eq!(terminal.state(), ActivationState::Terminal);
        assert_eq!(
            (
                backend.drain_calls,
                backend.terminal_calls,
                backend.cleanup_calls
            ),
            (1, 1, 1)
        );
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
        assert_terminal_reconciliation_leases_cleared(&terminal);
    }

    #[test]
    fn lost_drain_response_fences_dispatch_and_retries_only_idempotent_drain() {
        let active = active_snapshot(
            PluginActivationId::new("lost-drain").unwrap(),
            PluginDigest::from_bytes([5; 32]),
            PluginGeneration::INITIAL,
        );
        let mut backend = LostDrainThenSuccess::default();

        let uncertain = active.begin_draining_with_backend(&mut backend).unwrap();
        assert_eq!(uncertain.state(), ActivationState::Uncertain);
        assert_eq!(backend.drain_calls, 1);

        let draining = uncertain.begin_draining_with_backend(&mut backend).unwrap();
        assert_eq!(draining.state(), ActivationState::Draining);
        assert_eq!(backend.drain_calls, 2);
    }

    #[test]
    fn cleanup_retry_does_not_repeat_terminal_boundary() {
        let active = active_snapshot(
            PluginActivationId::new("cleanup-retry").unwrap(),
            PluginDigest::from_bytes([6; 32]),
            PluginGeneration::INITIAL,
        );
        let mut backend = LostCleanupThenSuccess::default();
        let draining = active.begin_draining_with_backend(&mut backend).unwrap();

        let uncertain = draining.terminal_with_backend(&mut backend).unwrap();
        assert_eq!(uncertain.state(), ActivationState::Uncertain);
        assert_eq!((backend.terminal_calls, backend.cleanup_calls), (1, 1));

        let terminal = uncertain.terminal_with_backend(&mut backend).unwrap();
        assert_eq!(terminal.state(), ActivationState::Terminal);
        assert_eq!((backend.terminal_calls, backend.cleanup_calls), (1, 2));
    }

    #[test]
    fn mismatched_drain_evidence_fences_dispatch_and_becomes_uncertain() {
        let active = active_snapshot(
            PluginActivationId::new("mismatched-drain").unwrap(),
            PluginDigest::from_bytes([7; 32]),
            PluginGeneration::INITIAL,
        );
        let other = active_snapshot(
            PluginActivationId::new("other-drain").unwrap(),
            PluginDigest::from_bytes([8; 32]),
            PluginGeneration::INITIAL,
        );
        let mut backend = MismatchedDrain {
            evidence: Some(PluginDrainEvidence::certified(
                other.process_lease.as_ref().unwrap(),
            )),
        };

        let uncertain = active.begin_draining_with_backend(&mut backend).unwrap();
        assert_eq!(uncertain.state(), ActivationState::Uncertain);
        assert!(uncertain.active_fence.is_none());
    }

    #[test]
    fn mismatched_cleanup_retains_terminal_evidence_for_retry() {
        let active = active_snapshot(
            PluginActivationId::new("mismatched-cleanup").unwrap(),
            PluginDigest::from_bytes([9; 32]),
            PluginGeneration::INITIAL,
        );
        let other = active_snapshot(
            PluginActivationId::new("other-cleanup").unwrap(),
            PluginDigest::from_bytes([10; 32]),
            PluginGeneration::INITIAL,
        );
        let mut backend = MismatchedCleanupThenSuccess {
            terminal_calls: 0,
            cleanup_calls: 0,
            mismatched: Some(PluginCleanupEvidence::certified(
                other.process_lease.as_ref().unwrap(),
            )),
        };
        let draining = active.begin_draining_with_backend(&mut backend).unwrap();

        let uncertain = draining.terminal_with_backend(&mut backend).unwrap();
        assert_eq!(uncertain.state(), ActivationState::Uncertain);
        assert_eq!((backend.terminal_calls, backend.cleanup_calls), (1, 1));

        let terminal = uncertain.terminal_with_backend(&mut backend).unwrap();
        assert_eq!(terminal.state(), ActivationState::Terminal);
        assert_eq!((backend.terminal_calls, backend.cleanup_calls), (1, 2));
    }
