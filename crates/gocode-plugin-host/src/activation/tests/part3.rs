    #[test]
    fn hook_dispatch_is_ordered_fenced_and_applies_failure_policy() {
        let mut registry = PluginAuthorityRegistry::built_in();
        let source = fixture_source();
        let package = registry
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "hook-dispatch");
        let mut process = CountingProcess::success();
        let mut handshake = exact_v2_transport(&request);
        let active = request.activate_with_reservation(
            &mut process,
            &mut handshake,
            &CountingRegistry::new(&registry),
            &Starts,
        );
        let definitions = vec![
            PluginHookDefinition::new(
                20,
                PluginId::new("builtin").unwrap(),
                PluginHookId::new("optional").unwrap(),
                PluginHookFailurePolicy::Optional,
            ),
            PluginHookDefinition::new(
                10,
                PluginId::new("builtin").unwrap(),
                PluginHookId::new("required").unwrap(),
                PluginHookFailurePolicy::Required,
            ),
            PluginHookDefinition::new(
                10,
                PluginId::new("builtin").unwrap(),
                PluginHookId::new("security").unwrap(),
                PluginHookFailurePolicy::Security,
            ),
        ];
        let definitions =
            verify_plugin_hook_descriptors(&definitions, &active, &registry, &AcceptDescriptors)
                .unwrap();
        let invocation = PluginHookInvocation::try_new(
            PluginHookInvocationId::new("dispatch-1").unwrap(),
            100,
            b"immutable-input".to_vec(),
        )
        .unwrap();
        let mut transport = HookTransport::new(vec![0, 2, 2]);

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
                .map(|result| result.definition().hook_id().as_str())
                .collect::<Vec<_>>(),
            ["required", "security", "optional"]
        );
        assert_eq!(
            dispatch
                .results()
                .iter()
                .map(|result| result.disposition())
                .collect::<Vec<_>>(),
            [
                PluginHookDisposition::Completed,
                PluginHookDisposition::Failed,
                PluginHookDisposition::Failed,
            ]
        );
        assert!(!dispatch.guarded_operation_allowed());
        assert_eq!(transport.send_calls, 3);

        registry.advance().unwrap();
        let mut fenced_transport = HookTransport::new(vec![]);
        let fenced = dispatch_hooks(
            &definitions,
            &invocation,
            &active,
            &registry,
            &registry,
            &Clock(1),
            &mut fenced_transport,
        )
        .unwrap();
        assert!(
            fenced
                .results()
                .iter()
                .all(|result| result.disposition() == PluginHookDisposition::Denied)
        );
        assert_eq!(fenced_transport.send_calls, 0);
    }

    #[test]
    fn optional_hook_transport_loss_is_uncertain_but_isolated() {
        let registry = PluginAuthorityRegistry::built_in();
        let source = fixture_source();
        let package = registry
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "optional-hook");
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
            PluginHookId::new("optional").unwrap(),
            PluginHookFailurePolicy::Optional,
        )];
        let definitions =
            verify_plugin_hook_descriptors(&definitions, &active, &registry, &AcceptDescriptors)
                .unwrap();
        let invocation = PluginHookInvocation::try_new(
            PluginHookInvocationId::new("dispatch-2").unwrap(),
            100,
            vec![],
        )
        .unwrap();
        let mut transport = HookTransport::lost_response();

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
            dispatch.results()[0].disposition(),
            PluginHookDisposition::Uncertain
        );
        assert!(dispatch.guarded_operation_allowed());
    }
