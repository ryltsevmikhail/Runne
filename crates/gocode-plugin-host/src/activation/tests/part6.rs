    #[test]
    fn hook_owner_mismatch_rejects_before_transport() {
        let registry = PluginAuthorityRegistry::built_in();
        let source = fixture_source();
        let package = registry
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "owner-mismatch");
        let mut process = CountingProcess::success();
        let mut handshake = exact_v2_transport(&request);
        let active = request.activate_with_reservation(
            &mut process,
            &mut handshake,
            &CountingRegistry::new(&registry),
            &Starts,
        );
        let definition = [PluginHookDefinition::new(
            0,
            PluginId::new("other").unwrap(),
            PluginHookId::new("hook").unwrap(),
            PluginHookFailurePolicy::Security,
        )];
        assert!(matches!(
            verify_plugin_hook_descriptors(&definition, &active, &registry, &AcceptDescriptors,),
            Err(PluginHookDispatchError::OwnerMismatch)
        ));
    }

    #[test]
    fn hook_fence_is_revalidated_before_each_send() {
        let registry = PluginAuthorityRegistry::built_in();
        let source = fixture_source();
        let package = registry
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        let request = request_with(package, "mid-batch-fence");
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
                PluginHookId::new("second").unwrap(),
                PluginHookFailurePolicy::Required,
            ),
        ];
        let definitions =
            verify_plugin_hook_descriptors(&definitions, &active, &registry, &AcceptDescriptors)
                .unwrap();
        let invocation = PluginHookInvocation::try_new(
            PluginHookInvocationId::new("dispatch-4").unwrap(),
            100,
            vec![],
        )
        .unwrap();
        let mut transport = HookTransport::new(vec![0]);
        let fence = FenceAfterFirst {
            validations: Cell::new(0),
        };

        let dispatch = dispatch_hooks(
            &definitions,
            &invocation,
            &active,
            &fence,
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
                PluginHookDisposition::Completed,
                PluginHookDisposition::Denied
            ]
        );
        assert_eq!(transport.send_calls, 1);
        assert!(!dispatch.guarded_operation_allowed());
    }

    struct FenceAfterFirst {
        validations: Cell<usize>,
    }

    impl PluginGenerationPort for FenceAfterFirst {
        fn acquire_read_lease(
            &self,
            _: &PluginActivationId,
        ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
            Err(PluginGenerationPortError::Unavailable)
        }

        fn ready_compare_and_set(
            &self,
            _: &PluginGenerationReadLease,
        ) -> Result<(), PluginGenerationPortError> {
            Err(PluginGenerationPortError::Unavailable)
        }

        fn validate_active(&self, _: &PluginActiveFence) -> Result<(), PluginGenerationPortError> {
            let current = self.validations.get();
            self.validations.set(current + 1);
            if current == 0 {
                Ok(())
            } else {
                Err(PluginGenerationPortError::Unavailable)
            }
        }
    }

    struct Clock(u64);

    struct AcceptDescriptors;

    impl PluginHookDescriptorAuthorityPort for AcceptDescriptors {
        fn accepts(&self, _: &PluginActivationSnapshot, _: [u8; 32]) -> bool {
            true
        }
    }

    struct AcceptToolDescriptors;

    impl PluginToolDescriptorAuthorityPort for AcceptToolDescriptors {
        fn accepts(&self, _: &PluginActivationSnapshot, _: [u8; 32]) -> bool {
            true
        }
    }

    impl PluginHookClockPort for Clock {
        fn now_tick(&self) -> u64 {
            self.0
        }
    }

    struct HookTransport {
        responses: Vec<u8>,
        request_digest: Option<[u8; 32]>,
        send_calls: usize,
        lost_response: bool,
    }

    impl HookTransport {
        fn new(mut responses: Vec<u8>) -> Self {
            responses.reverse();
            Self {
                responses,
                request_digest: None,
                send_calls: 0,
                lost_response: false,
            }
        }

        fn lost_response() -> Self {
            Self {
                responses: vec![],
                request_digest: None,
                send_calls: 0,
                lost_response: true,
            }
        }
    }

    impl PluginTransportPort for HookTransport {
        fn send(&mut self, outbound: PluginBootstrapFrame) -> Result<(), PluginTransportPortError> {
            assert!(!outbound.as_bytes().is_empty());
            Ok(())
        }

        fn send_before(
            &mut self,
            _: u64,
            outbound: PluginBootstrapFrame,
        ) -> Result<(), PluginTransportPortError> {
            self.send_calls += 1;
            let digest = outbound
                .as_bytes()
                .get(outbound.as_bytes().len().saturating_sub(32)..)
                .ok_or(PluginTransportPortError::NotSent)?;
            self.request_digest = Some(digest.try_into().unwrap());
            Ok(())
        }

        fn receive(&mut self, inbound: &mut [u8]) -> Result<usize, PluginTransportPortError> {
            self.receive_before(u64::MAX, inbound)
        }

        fn receive_before(
            &mut self,
            _: u64,
            inbound: &mut [u8],
        ) -> Result<usize, PluginTransportPortError> {
            if self.lost_response {
                return Err(PluginTransportPortError::ResponseLost);
            }
            inbound[..32].copy_from_slice(&self.request_digest.take().unwrap());
            inbound[32] = self.responses.pop().unwrap();
            Ok(33)
        }
    }

    fn active_snapshot(
        id: PluginActivationId,
        digest: PluginDigest,
        generation: PluginGeneration,
    ) -> PluginActivationSnapshot {
        let intent = PluginStartIntent::issued(id.clone(), digest, generation, [1; 32]);
        PluginActivationSnapshot {
            plugin_id: PluginId::new("builtin").unwrap(),
            activation_id: id.clone(),
            package_digest: digest,
            generation,
            negotiation_snapshot: ProtocolNegotiationSnapshotDigest::from_bytes([1; 32]),
            state: ActivationState::Active,
            process_lease: Some(PluginProcessLease::certified(&intent)),
            drain_evidence: None,
            terminal_evidence: None,
            start_intent: Some(intent),
            generation_lease: Some(PluginGenerationReadLease::issued(id, generation)),
            active_fence: None,
            history: vec![
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ]
            .into_boxed_slice(),
            receipts: PluginActivationSnapshot::bounded_receipts(vec![
                PluginActivationReceipt::StartAttempted,
            ]),
        }
    }
    fn hello(request: &PluginActivationRequest, profile: ProtocolProfileRef) -> BootstrapMessage {
        let mut profiles = BoundedProfileRefVec::new();
        profiles.push(profile).unwrap();
        let metadata = request.package.plugin_hello_metadata();
        BootstrapMessage::PluginHello(PluginHello {
            host_nonce: request.host_nonce(),
            plugin_nonce: Nonce::from_bytes([2; 16]),
            host_identity: metadata.host_identity,
            package_id: metadata.package_id,
            package_digest: PackageDigest::new(
                DigestAlgorithm::Sha256,
                *request.package_digest().as_bytes(),
            ),
            package_version: metadata.package_version,
            manifest_digest: metadata.manifest_digest,
            plugin_identity: metadata.plugin_identity,
            target_identity: metadata.target_identity,
            entrypoint: metadata.entrypoint,
            supported_profiles: profiles,
        })
    }
    fn ack(request: &PluginActivationRequest, profile: ProtocolProfileRef) -> BootstrapMessage {
        // Transport fixture encodes this V2 response only after ProfileSelected.
        BootstrapMessage::SelectionAcknowledged(
            gocode_plugin_protocol::bootstrap::SelectionAcknowledged {
                host_nonce: request.host_nonce(),
                plugin_nonce: Nonce::from_bytes([2; 16]),
                session_id: request.session_id(),
                profile_id: profile.profile_id().clone(),
                profile_digest: *profile.profile_digest(),
            },
        )
    }
