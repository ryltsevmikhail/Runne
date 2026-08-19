    struct Transport {
        frames: Vec<BootstrapMessage>,
        oversized: bool,
    }

    struct CountingProcess {
        start_calls: usize,
        result: ResultKind,
    }

    enum ResultKind {
        Success,
        BackendUnavailable,
    }

    impl CountingProcess {
        fn success() -> Self {
            Self {
                start_calls: 0,
                result: ResultKind::Success,
            }
        }

        fn backend_unavailable() -> Self {
            Self {
                start_calls: 0,
                result: ResultKind::BackendUnavailable,
            }
        }
    }

    impl PluginProcessPort for CountingProcess {
        fn start(
            &mut self,
            intent: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.start_calls += 1;
            match self.result {
                ResultKind::Success => Ok(PluginProcessLease::certified(intent)),
                ResultKind::BackendUnavailable => Err(PluginProcessPortError::BackendUnavailable),
            }
        }
    }

    struct CountingGeneration {
        fail_ready: bool,
        generation: PluginGeneration,
        ready_cas_calls: Cell<usize>,
    }

    trait ReadyCasCounter {
        fn ready_cas_calls(&self) -> usize;
    }

    impl ReadyCasCounter for CountingGeneration {
        fn ready_cas_calls(&self) -> usize {
            self.ready_cas_calls.get()
        }
    }

    impl CountingGeneration {
        fn current() -> Self {
            Self::at(PluginGeneration::INITIAL)
        }

        fn at(generation: PluginGeneration) -> Self {
            Self {
                fail_ready: false,
                generation,
                ready_cas_calls: Cell::new(0),
            }
        }

        fn failing_ready() -> Self {
            Self {
                fail_ready: true,
                ..Self::current()
            }
        }
    }

    impl PluginGenerationPort for CountingGeneration {
        fn acquire_read_lease(
            &self,
            id: &PluginActivationId,
        ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
            Ok(PluginGenerationReadLease::issued(
                id.clone(),
                self.generation,
            ))
        }

        fn ready_compare_and_set(
            &self,
            _: &PluginGenerationReadLease,
        ) -> Result<(), PluginGenerationPortError> {
            self.ready_cas_calls.set(self.ready_cas_calls.get() + 1);
            if self.fail_ready {
                Err(PluginGenerationPortError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    struct CountingRegistry<'a> {
        registry: &'a PluginAuthorityRegistry,
        ready_cas_calls: Cell<usize>,
    }

    impl<'a> CountingRegistry<'a> {
        fn new(registry: &'a PluginAuthorityRegistry) -> Self {
            Self {
                registry,
                ready_cas_calls: Cell::new(0),
            }
        }
    }

    impl PluginGenerationPort for CountingRegistry<'_> {
        fn acquire_read_lease(
            &self,
            id: &PluginActivationId,
        ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
            self.registry.acquire_read_lease(id)
        }

        fn ready_compare_and_set(
            &self,
            lease: &PluginGenerationReadLease,
        ) -> Result<(), PluginGenerationPortError> {
            self.ready_cas_calls.set(self.ready_cas_calls.get() + 1);
            self.registry.ready_compare_and_set(lease)
        }

        fn publish_active(
            &self,
            lease: &PluginGenerationReadLease,
            negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
        ) -> Result<PluginActiveFence, PluginGenerationPortError> {
            self.ready_cas_calls.set(self.ready_cas_calls.get() + 1);
            self.registry.publish_active(lease, negotiation_snapshot)
        }

        fn validate_active(
            &self,
            fence: &PluginActiveFence,
        ) -> Result<(), PluginGenerationPortError> {
            self.registry.validate_active(fence)
        }
    }

    impl ReadyCasCounter for CountingRegistry<'_> {
        fn ready_cas_calls(&self) -> usize {
            self.ready_cas_calls.get()
        }
    }

    enum WireResponse {
        V1(BootstrapMessage),
        V2(SelectionAcknowledgedV2),
        Oversized,
    }

    struct CountingTransport {
        responses: Vec<WireResponse>,
        write_calls: usize,
        read_calls: usize,
    }

    impl CountingTransport {
        fn new(responses: Vec<WireResponse>) -> Self {
            Self {
                responses,
                write_calls: 0,
                read_calls: 0,
            }
        }

        fn oversized() -> Self {
            Self::new(vec![WireResponse::Oversized])
        }
    }

    impl PluginTransportPort for CountingTransport {
        fn send(&mut self, outbound: PluginBootstrapFrame) -> Result<(), PluginTransportPortError> {
            self.write_calls += 1;
            assert!(!outbound.as_bytes().is_empty());
            Ok(())
        }

        fn receive(&mut self, inbound: &mut [u8]) -> Result<usize, PluginTransportPortError> {
            let response = self.responses.remove(0);
            self.read_calls += 1;
            match response {
                WireResponse::Oversized => Ok(inbound.len() + 1),
                WireResponse::V1(message) => {
                    let frame = encode_frame(
                        &message,
                        &FrameLimits {
                            max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                        },
                    )
                    .unwrap();
                    inbound[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
                WireResponse::V2(ack) => {
                    let frame = runne_plugin_protocol::frame::encode_codec_frame(
                        &ack,
                        &FrameLimits {
                            max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                        },
                    )
                    .unwrap();
                    inbound[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
            }
        }
    }
