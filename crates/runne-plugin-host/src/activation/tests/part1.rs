    #[test]
    fn certified_evidence_can_terminalize_exact_draining_snapshot_once() {
        let id = PluginActivationId::new("fixture").unwrap();
        let digest = PluginDigest::from_bytes([1; 32]);
        let generation = PluginGeneration::INITIAL;
        let active = active_snapshot(id, digest, generation);
        let evidence = PluginTerminalEvidence::certified(&active);
        let terminal = active.begin_draining().unwrap().terminal(evidence).unwrap();
        assert_eq!(terminal.state(), ActivationState::Terminal);
    }

    #[test]
    fn invalid_terminal_evidence_returns_the_original_draining_snapshot_for_retry() {
        let id = PluginActivationId::new("retry-terminal").unwrap();
        let digest = PluginDigest::from_bytes([1; 32]);
        let generation = PluginGeneration::INITIAL;
        let draining = active_snapshot(id.clone(), digest, generation)
            .begin_draining()
            .unwrap();
        let other = active_snapshot(
            PluginActivationId::new("other").unwrap(),
            digest,
            generation,
        );
        let invalid_evidence = PluginTerminalEvidence::certified(&other);
        let valid_evidence = PluginTerminalEvidence::certified(&draining);

        let (draining, error) = *draining.terminal(invalid_evidence).unwrap_err();
        assert_eq!(error, PluginLifecycleError::InvalidTerminalEvidence);
        assert_eq!(draining.state(), ActivationState::Draining);
        assert!(draining.process_lease.is_some());
        assert!(draining.generation_lease.is_some());

        assert_eq!(
            draining.terminal(valid_evidence).unwrap().state(),
            ActivationState::Terminal
        );
    }

    #[test]
    fn certified_fixtures_exercise_handshake_and_fail_closed_branches() {
        let request = request();
        let profile = request.protocol_profile();
        let active = request.activate_with_reservation(
            &mut Process::default(),
            &mut Transport::new(vec![
                hello(&request, profile.clone()),
                ack(&request, profile.clone()),
            ]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(active.state(), ActivationState::Active);
        assert_eq!(
            active.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ]
        );

        let reflected = BootstrapMessage::ProfileSelected(ProfileSelected {
            host_nonce: request.host_nonce(),
            plugin_nonce: Nonce::from_bytes([2; 16]),
            session_id: request.session_id(),
            profile_id: profile.profile_id().clone(),
            profile_digest: *profile.profile_digest(),
        });
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![hello(&request, profile.clone()), reflected]),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );

        let mut wrong_identity = hello(&request, profile.clone());
        if let BootstrapMessage::PluginHello(value) = &mut wrong_identity {
            value.plugin_identity =
                HostExecutionIdentity::Plugin(PluginIdentity::new("different-plugin").unwrap());
        }
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![wrong_identity]),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );

        let mut wrong_nonce = hello(&request, profile.clone());
        if let BootstrapMessage::PluginHello(value) = &mut wrong_nonce {
            value.host_nonce = Nonce::from_bytes([9; 16]);
        }
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![wrong_nonce]),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );

        let recombined = ProtocolProfileRef::new(
            profile.profile_id().clone(),
            ProfileDigest::from_bytes([9; 32]),
        );
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![hello(&request, recombined)]),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::oversized(),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![
                        hello(&request, profile.clone()),
                        ack(&request, profile)
                    ]),
                    &Generation {
                        fail_ready: true,
                        generation: PluginGeneration::INITIAL
                    },
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );

        let uncertain = active.begin_draining().unwrap().uncertain().unwrap();
        assert_eq!(uncertain.state(), ActivationState::Uncertain);
    }

    fn request() -> PluginActivationRequest {
        let source = fixture_source();
        let package = PluginAuthorityRegistry::built_in()
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        request_with(package, "fixture-handshake")
    }

    fn fixture_source() -> crate::PluginPackageSource {
        crate::PluginPackageCapture::capture(
            crate::PluginPackageContent::new(
                b"runne-plugin-host/builtin-package-v1".to_vec(),
                b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\n".to_vec(),
                b"runne-plugin-host/builtin-entrypoint-v1".to_vec(),
                b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\n".to_vec(),
                b"runne-plugin-host/builtin-trust-binding-v1".to_vec(),
            ),
            PluginClass::Extension,
        )
    }

    fn request_with(
        package: crate::VerifiedPluginPackage,
        activation_id: &str,
    ) -> PluginActivationRequest {
        PluginActivationRequest::new(
            package,
            PluginActivationId::new(activation_id).unwrap(),
            Nonce::from_bytes([1; 16]),
            ProtocolSessionId::from_bytes([7, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]),
        )
    }
