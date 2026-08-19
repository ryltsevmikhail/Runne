    #[test]
    fn registry_advance_requires_reverification_before_a_fresh_generation_can_activate() {
        let mut registry = PluginAuthorityRegistry::built_in();
        let old_source = fixture_source();
        let old_package = registry
            .verifier_for(&old_source)
            .unwrap()
            .verify(old_source)
            .unwrap();
        let old_request = request_with(old_package, "generation-old");
        let initial_snapshot_binding = old_request.package.negotiation_snapshot();
        let mut initial_process = CountingProcess::success();
        let mut initial_transport = exact_v2_transport(&old_request);
        let initial_generation = CountingRegistry::new(&registry);
        let active = old_request.activate_with_reservation(
            &mut initial_process,
            &mut initial_transport,
            &initial_generation,
            &Starts,
        );
        assert_eq!(active.state(), ActivationState::Active);
        assert_eq!(active.negotiation_snapshot(), initial_snapshot_binding);
        assert_stage_case(
            &active,
            ActivationState::Active,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &initial_process,
            &initial_transport,
            &initial_generation,
            (1, 2, 2, 1),
        );
        assert!(active.is_dispatchable(&registry));
        registry.advance().unwrap();
        assert!(!active.is_dispatchable(&registry));

        let mut stale_process = CountingProcess::success();
        let mut stale_transport = CountingTransport::new(vec![]);
        let stale_generation = CountingRegistry::new(&registry);
        let stale = old_request.activate_with_reservation(
            &mut stale_process,
            &mut stale_transport,
            &stale_generation,
            &Starts,
        );
        assert_stage_case(
            &stale,
            ActivationState::Verified,
            &[ActivationState::Verified],
            &[],
            false,
            &stale_process,
            &stale_transport,
            &stale_generation,
            (0, 0, 0, 0),
        );

        let new_source = fixture_source();
        let new_package = registry
            .verifier_for(&new_source)
            .unwrap()
            .verify(new_source)
            .unwrap();
        let new_request = request_with(new_package, "generation-new");
        let renewed_snapshot_binding = new_request.package.negotiation_snapshot();
        let mut renewed_process = CountingProcess::success();
        let mut renewed_transport = exact_v2_transport(&new_request);
        let renewed_generation = CountingRegistry::new(&registry);
        let renewed = new_request.activate_with_reservation(
            &mut renewed_process,
            &mut renewed_transport,
            &renewed_generation,
            &Starts,
        );
        assert_eq!(renewed.state(), ActivationState::Active);
        assert_eq!(renewed.negotiation_snapshot(), renewed_snapshot_binding);
        assert_eq!(renewed.generation(), PluginGeneration::new(2).unwrap());
        assert_stage_case(
            &renewed,
            ActivationState::Active,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &renewed_process,
            &renewed_transport,
            &renewed_generation,
            (1, 2, 2, 1),
        );
        assert!(renewed.is_dispatchable(&registry));
        assert_ne!(active.generation(), renewed.generation());
        assert_eq!(
            active.retained_generation_lease_generation(),
            Some(PluginGeneration::INITIAL)
        );
        assert_eq!(
            renewed.retained_generation_lease_generation(),
            Some(PluginGeneration::new(2).unwrap())
        );
        assert_ne!(
            active.negotiation_snapshot(),
            renewed.negotiation_snapshot()
        );
    }
