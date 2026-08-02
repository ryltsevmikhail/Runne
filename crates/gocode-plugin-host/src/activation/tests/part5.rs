    #[test]
    fn open_hook_claim_blocks_generation_advance_until_closed() {
        let journal = Arc::new(SharedHookJournal::default());
        let mut registry =
            PluginAuthorityRegistry::built_in_with_hook_dispatch_journal(journal.clone());
        let source = fixture_source();
        let package = registry
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "open-claim");
        let mut process = CountingProcess::success();
        let mut handshake = exact_v2_transport(&request);
        let active = request.activate_with_reservation(
            &mut process,
            &mut handshake,
            &CountingRegistry::new(&registry),
            &Starts,
        );
        let definition = PluginHookDefinition::new(
            0,
            PluginId::new("builtin").unwrap(),
            PluginHookId::new("effect").unwrap(),
            PluginHookFailurePolicy::Required,
        );
        let _verified = verify_plugin_hook_descriptors(
            std::slice::from_ref(&definition),
            &active,
            &registry,
            &AcceptDescriptors,
        )
        .unwrap();
        let invocation = PluginHookInvocation::try_new(
            PluginHookInvocationId::new("open-invocation").unwrap(),
            100,
            vec![],
        )
        .unwrap();
        let claim = match registry
            .claim(&active, &definition, &invocation, [9; 32])
            .unwrap()
        {
            crate::PluginHookDispatchClaimResult::Fresh(claim) => claim,
            crate::PluginHookDispatchClaimResult::Existing(_) => panic!("fresh fixture"),
        };

        assert_eq!(
            registry.advance(),
            Err(crate::package::RegistryAdvanceError::OpenDispatch)
        );
        assert!(journal.next_recovered_dispatch().unwrap().is_none());
        drop(claim);
        drop(registry);
        journal.fence_prior_owner_for_recovery();
        let recovered = journal.next_recovered_dispatch().unwrap().unwrap();
        assert_eq!(recovered.key().activation_id(), active.activation_id());
        assert_eq!(recovered.key().generation(), active.generation());
        assert_eq!(recovered.key().plugin_id(), active.plugin_id());

        let mut reconstructed =
            PluginAuthorityRegistry::built_in_with_hook_dispatch_journal(journal);
        let forged = crate::PluginHookRecoveredDispatch::new(
            recovered.key().clone(),
            *recovered.request_digest(),
            [0; 32],
        );
        assert_eq!(
            reconstructed.quarantine_recovered(&forged),
            Err(PluginHookDispatchError::IntentConflict)
        );
        reconstructed.quarantine_recovered(&recovered).unwrap();
        assert!(reconstructed.advance().is_ok());
    }

    #[test]
    fn active_toolset_is_descriptor_bound_and_fenced_after_generation_advance() {
        let mut registry = PluginAuthorityRegistry::built_in();
        let activation_source = fixture_source();
        let activation_package = registry
            .verifier_for(&activation_source)
            .unwrap()
            .verify(activation_source)
            .unwrap();
        let descriptor_source = fixture_source();
        let descriptor_package = registry
            .verifier_for(&descriptor_source)
            .unwrap()
            .verify(descriptor_source)
            .unwrap();
        let request = request_with(activation_package, "active-tools");
        let mut process = CountingProcess::success();
        let mut handshake = exact_v2_transport(&request);
        let active = request.activate_with_reservation(
            &mut process,
            &mut handshake,
            &CountingRegistry::new(&registry),
            &Starts,
        );
        let verified = verify_plugin_tool_descriptors(
            &descriptor_package,
            &active,
            &registry,
            vec![PluginToolDescriptor::new(
                PluginId::new("builtin").unwrap(),
                ToolId::new("builtin::search").unwrap(),
                ToolVersion::new("1.0.0").unwrap(),
                json!({"type": "object"}),
            )],
            &AcceptToolDescriptors,
        )
        .unwrap();
        let toolset = activate_plugin_tools(verified, &active, &registry).unwrap();
        let tool_ref = &toolset.snapshot().tool_refs()[0];
        let binding = toolset.bind_dispatch(tool_ref, &active, &registry).unwrap();
        assert_eq!(binding.tool_ref(), tool_ref);
        assert_eq!(binding.activation_id(), active.activation_id().as_str());
        assert_eq!(binding.generation(), active.generation().get());
        assert_eq!(
            binding.descriptor_snapshot_digest(),
            toolset.descriptor_snapshot_digest()
        );
        let starts = Arc::new(Mutex::new(0));
        let gateway = ToolGateway::new(
            AllowToolAdmission,
            CountingToolExecutor {
                starts: Arc::clone(&starts),
            },
            ToolOutputBounds::new(1024, 16, 16).unwrap(),
        );
        assert!(
            toolset
                .dispatch_via_gateway(
                    tool_ref,
                    &active,
                    &registry,
                    &gateway,
                    "plugin-tool-invocation".into(),
                    [7; 32],
                )
                .is_ok()
        );
        assert_eq!(*starts.lock().unwrap(), 1);

        registry.advance().unwrap();
        assert!(toolset.bind_dispatch(tool_ref, &active, &registry).is_err());
        assert!(
            toolset
                .dispatch_via_gateway(
                    tool_ref,
                    &active,
                    &registry,
                    &gateway,
                    "stale-plugin-tool-invocation".into(),
                    [8; 32],
                )
                .is_err()
        );
        assert_eq!(*starts.lock().unwrap(), 1);
    }
