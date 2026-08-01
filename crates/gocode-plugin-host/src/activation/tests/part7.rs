    #[test]
    fn stale_generation_is_rejected_before_process_start() {
        let mut process = Process::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::at(PluginGeneration::new(2).unwrap()),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Verified);
        assert_eq!(process.calls, 0);
        assert_eq!(snapshot.transition_history(), [ActivationState::Verified]);
    }

    #[test]
    fn activation_stage_matrix_stale_generation_has_no_boundary_calls() {
        let mut process = CountingProcess::success();
        let mut transport = CountingTransport::new(vec![]);
        let generation = CountingGeneration::at(PluginGeneration::new(2).unwrap());

        let snapshot =
            request().activate_with_reservation(&mut process, &mut transport, &generation, &Starts);

        assert_eq!(snapshot.state(), ActivationState::Verified);
        assert_eq!(snapshot.transition_history(), [ActivationState::Verified]);
        assert_eq!(snapshot.attempt_receipts(), []);
        assert_no_reconciliation_leases(&snapshot);
        assert_eq!(process.start_calls, 0);
        assert_eq!(transport.write_calls, 0);
        assert_eq!(transport.read_calls, 0);
        assert_eq!(generation.ready_cas_calls.get(), 0);
    }

    #[test]
    fn activation_stage_matrix_backend_unavailable_stops_before_transport() {
        let request = request();
        let mut process = CountingProcess::backend_unavailable();
        let mut transport = CountingTransport::new(vec![]);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_stage_case(
            &snapshot,
            ActivationState::Verified,
            &[ActivationState::Verified],
            &[
                PluginActivationReceipt::StartAttempted,
                PluginActivationReceipt::StartProvenNotStarted,
            ],
            false,
            &process,
            &transport,
            &generation,
            (1, 0, 0, 0),
        );
    }

    #[test]
    fn activation_stage_matrix_v1_downgrade_to_legacy_profile_is_uncertain() {
        let request = request();
        let mut peer = peer_hello(&request);
        let authority = request.protocol_profile();
        assert_eq!(authority.profile_id().as_str(), "builtin-profile-v2");
        assert_eq!(
            authority.profile_digest().as_bytes(),
            request.package.protocol_profile_digest().as_bytes()
        );
        let mut legacy_profiles = BoundedProfileRefVec::new();
        legacy_profiles
            .push(ProtocolProfileRef::new(
                ProfileId::new("builtin-profile-v1").unwrap(),
                ProfileDigest::from_bytes([1; 32]),
            ))
            .unwrap();
        peer.supported_profiles = legacy_profiles;
        let mut process = CountingProcess::success();
        let mut transport =
            CountingTransport::new(vec![WireResponse::V1(BootstrapMessage::PluginHello(peer))]);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_uncertain_after_first_exchange(&snapshot, &process, &transport, &generation);
    }

    #[test]
    fn activation_stage_matrix_plugin_hello_identity_mismatch_is_uncertain() {
        let request = request();
        let mut peer = peer_hello(&request);
        peer.plugin_identity =
            HostExecutionIdentity::Plugin(PluginIdentity::new("different-plugin").unwrap());
        assert_first_exchange_failure(request, BootstrapMessage::PluginHello(peer));
    }

    #[test]
    fn activation_stage_matrix_nonce_mismatch_is_uncertain() {
        let request = request();
        let mut peer = peer_hello(&request);
        peer.host_nonce = Nonce::from_bytes([9; 16]);
        assert_first_exchange_failure(request, BootstrapMessage::PluginHello(peer));
    }

    #[test]
    fn activation_stage_matrix_profile_recombination_is_uncertain() {
        let request = request();
        let mut peer = peer_hello(&request);
        let profile = request.protocol_profile();
        let mut profiles = BoundedProfileRefVec::new();
        profiles
            .push(ProtocolProfileRef::new(
                profile.profile_id().clone(),
                ProfileDigest::from_bytes([9; 32]),
            ))
            .unwrap();
        peer.supported_profiles = profiles;
        assert_first_exchange_failure(request, BootstrapMessage::PluginHello(peer));
    }

    #[test]
    fn activation_stage_matrix_oversized_first_inbound_frame_is_uncertain() {
        let request = request();
        let mut process = CountingProcess::success();
        let mut transport = CountingTransport::oversized();
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_uncertain_after_first_exchange(&snapshot, &process, &transport, &generation);
    }

    #[test]
    fn activation_stage_matrix_reflected_v1_selection_as_ack_is_uncertain() {
        let request = request();
        let profile = request.protocol_profile();
        let reflected = BootstrapMessage::ProfileSelected(ProfileSelected {
            host_nonce: request.host_nonce(),
            plugin_nonce: Nonce::from_bytes([2; 16]),
            session_id: request.session_id(),
            profile_id: profile.profile_id().clone(),
            profile_digest: *profile.profile_digest(),
        });
        let mut process = CountingProcess::success();
        let mut transport = CountingTransport::new(vec![
            WireResponse::V1(BootstrapMessage::PluginHello(peer_hello(&request))),
            WireResponse::V1(reflected),
        ]);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_stage_case(
            &snapshot,
            ActivationState::Uncertain,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Uncertain,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &process,
            &transport,
            &generation,
            (1, 2, 2, 0),
        );
    }

    #[test]
    fn activation_stage_matrix_ready_cas_failure_is_uncertain() {
        let request = request();
        let mut process = CountingProcess::success();
        let mut transport = exact_v2_transport(&request);
        let generation = CountingGeneration::failing_ready();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_stage_case(
            &snapshot,
            ActivationState::Uncertain,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Uncertain,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &process,
            &transport,
            &generation,
            (1, 2, 2, 1),
        );
    }

    #[test]
    fn activation_stage_matrix_exact_v2_success_is_active() {
        let request = request();
        let mut process = CountingProcess::success();
        let mut transport = exact_v2_transport(&request);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_stage_case(
            &snapshot,
            ActivationState::Active,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &process,
            &transport,
            &generation,
            (1, 2, 2, 1),
        );
    }
