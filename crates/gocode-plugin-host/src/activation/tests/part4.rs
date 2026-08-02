    #[test]
    fn uncertain_hook_response_stops_channel_before_next_hook() {
        let registry = PluginAuthorityRegistry::built_in();
        let source = fixture_source();
        let package = registry
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "uncertain-channel");
        let mut process = CountingProcess::success();
        let mut handshake = exact_v2_transport(&request);
        let active = request.activate_with_reservation(
            &mut process,
            &mut handshake,
            &CountingRegistry::new(&registry),
            &Starts,
        );
        let definitions = [
            PluginHookDefinition::new(
                0,
                PluginId::new("builtin").unwrap(),
                PluginHookId::new("first").unwrap(),
                PluginHookFailurePolicy::Optional,
            ),
            PluginHookDefinition::new(
                1,
                PluginId::new("builtin").unwrap(),
                PluginHookId::new("security").unwrap(),
                PluginHookFailurePolicy::Security,
            ),
        ];
        let definitions =
            verify_plugin_hook_descriptors(&definitions, &active, &registry, &AcceptDescriptors)
                .unwrap();
        let invocation = PluginHookInvocation::try_new(
            PluginHookInvocationId::new("dispatch-uncertain").unwrap(),
            100,
            vec![],
        )
        .unwrap();
        let mut transport = HookTransport::new(vec![3]);

        let dispatch = dispatch_hooks(
            &definitions,
            &invocation,
            &active,
            &registry,
            &registry,
            &Clock(1),
            &mut transport,
        )
        .unwrap();

        assert_eq!(
            dispatch
                .results()
                .iter()
                .map(|result| result.disposition())
                .collect::<Vec<_>>(),
            [
                PluginHookDisposition::Uncertain,
                PluginHookDisposition::Denied
            ]
        );
        assert_eq!(transport.send_calls, 1);
        assert!(!dispatch.guarded_operation_allowed());
    }

    #[test]
    fn exact_hook_replay_returns_prior_outcome_without_second_send() {
        let registry = PluginAuthorityRegistry::built_in();
        let source = fixture_source();
        let package = registry
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "exact-hook-replay");
        let mut process = CountingProcess::success();
        let mut handshake = exact_v2_transport(&request);
        let active = request.activate_with_reservation(
            &mut process,
            &mut handshake,
            &CountingRegistry::new(&registry),
            &Starts,
        );
        let definitions = [PluginHookDefinition::new(
            0,
            PluginId::new("builtin").unwrap(),
            PluginHookId::new("effect").unwrap(),
            PluginHookFailurePolicy::Required,
        )];
        let definitions =
            verify_plugin_hook_descriptors(&definitions, &active, &registry, &AcceptDescriptors)
                .unwrap();
        let invocation = PluginHookInvocation::try_new(
            PluginHookInvocationId::new("same-invocation").unwrap(),
            100,
            b"same-payload".to_vec(),
        )
        .unwrap();

        let mut first_transport = HookTransport::new(vec![0]);
        let first = dispatch_hooks(
            &definitions,
            &invocation,
            &active,
            &registry,
            &registry,
            &Clock(1),
            &mut first_transport,
        )
        .unwrap();
        let mut replay_transport = HookTransport::new(vec![2]);
        let replay = dispatch_hooks(
            &definitions,
            &invocation,
            &active,
            &registry,
            &registry,
            &Clock(1),
            &mut replay_transport,
        )
        .unwrap();

        assert_eq!(
            first.results()[0].disposition(),
            PluginHookDisposition::Completed
        );
        assert_eq!(
            replay.results()[0].disposition(),
            PluginHookDisposition::Completed
        );
        assert_eq!(first_transport.send_calls, 1);
        assert_eq!(replay_transport.send_calls, 0);

        let changed = PluginHookInvocation::try_new(
            PluginHookInvocationId::new("same-invocation").unwrap(),
            100,
            b"changed-payload".to_vec(),
        )
        .unwrap();
        let mut conflict_transport = HookTransport::new(vec![0]);
        assert_eq!(
            dispatch_hooks(
                &definitions,
                &changed,
                &active,
                &registry,
                &registry,
                &Clock(1),
                &mut conflict_transport,
            ),
            Err(PluginHookDispatchError::IntentConflict)
        );
        assert_eq!(conflict_transport.send_calls, 0);
    }

    #[test]
    fn hook_replay_survives_authority_reconstruction_with_shared_journal() {
        let journal: Arc<dyn PluginHookDispatchJournal> = Arc::new(SharedHookJournal::default());
        let registry =
            PluginAuthorityRegistry::built_in_with_hook_dispatch_journal(Arc::clone(&journal));
        let source = fixture_source();
        let package = registry
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "restart-hook-replay");
        let mut process = CountingProcess::success();
        let mut handshake = exact_v2_transport(&request);
        let active = request.activate_with_reservation(
            &mut process,
            &mut handshake,
            &CountingRegistry::new(&registry),
            &Starts,
        );
        let definitions = [PluginHookDefinition::new(
            0,
            PluginId::new("builtin").unwrap(),
            PluginHookId::new("effect").unwrap(),
            PluginHookFailurePolicy::Required,
        )];
        let definitions =
            verify_plugin_hook_descriptors(&definitions, &active, &registry, &AcceptDescriptors)
                .unwrap();
        let invocation = PluginHookInvocation::try_new(
            PluginHookInvocationId::new("restart-invocation").unwrap(),
            100,
            b"same-payload".to_vec(),
        )
        .unwrap();
        let mut first_transport = HookTransport::new(vec![0]);
        let first = dispatch_hooks(
            &definitions,
            &invocation,
            &active,
            &registry,
            &registry,
            &Clock(1),
            &mut first_transport,
        )
        .unwrap();
        assert_eq!(
            first.results()[0].disposition(),
            PluginHookDisposition::Completed
        );
        assert_eq!(first_transport.send_calls, 1);
        drop(registry);

        let reconstructed = PluginAuthorityRegistry::built_in_with_hook_dispatch_journal(journal);
        let source = fixture_source();
        let package = reconstructed
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "restart-hook-replay");
        let mut process = CountingProcess::success();
        let mut handshake = exact_v2_transport(&request);
        let active = request.activate_with_reservation(
            &mut process,
            &mut handshake,
            &CountingRegistry::new(&reconstructed),
            &Starts,
        );
        let definitions = [PluginHookDefinition::new(
            0,
            PluginId::new("builtin").unwrap(),
            PluginHookId::new("effect").unwrap(),
            PluginHookFailurePolicy::Required,
        )];
        let verified = verify_plugin_hook_descriptors(
            &definitions,
            &active,
            &reconstructed,
            &AcceptDescriptors,
        )
        .unwrap();
        let mut replay_transport = HookTransport::new(vec![2]);
        let replay = dispatch_hooks(
            &verified,
            &invocation,
            &active,
            &reconstructed,
            &reconstructed,
            &Clock(1),
            &mut replay_transport,
        )
        .unwrap();

        assert_eq!(
            replay.results()[0].disposition(),
            PluginHookDisposition::Completed
        );
        assert_eq!(replay_transport.send_calls, 0);
    }
