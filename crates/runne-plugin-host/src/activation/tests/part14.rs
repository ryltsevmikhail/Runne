    fn peer_hello(request: &PluginActivationRequest) -> PluginHello {
        let metadata = request.package.plugin_hello_metadata();
        PluginHello {
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
            supported_profiles: request.package.advertised_profiles(),
        }
    }

    fn exact_v2_transport(request: &PluginActivationRequest) -> CountingTransport {
        let profile = request.protocol_profile();
        CountingTransport::new(vec![
            WireResponse::V1(BootstrapMessage::PluginHello(peer_hello(request))),
            WireResponse::V2(SelectionAcknowledgedV2 {
                host_nonce: request.host_nonce(),
                plugin_nonce: Nonce::from_bytes([2; 16]),
                session_id: request.session_id(),
                profile_id: profile.profile_id().clone(),
                profile_digest: *profile.profile_digest(),
            }),
        ])
    }
    impl Transport {
        fn new(frames: Vec<BootstrapMessage>) -> Self {
            Self {
                frames,
                oversized: false,
            }
        }
        fn oversized() -> Self {
            Self {
                frames: vec![],
                oversized: true,
            }
        }
    }
    impl PluginTransportPort for Transport {
        fn send(&mut self, outbound: PluginBootstrapFrame) -> Result<(), PluginTransportPortError> {
            assert!(!outbound.as_bytes().is_empty());
            Ok(())
        }

        fn receive(&mut self, inbound: &mut [u8]) -> Result<usize, PluginTransportPortError> {
            if self.oversized {
                return Ok(inbound.len() + 1);
            }
            let response = self.frames.remove(0);
            let frame = match response {
                BootstrapMessage::SelectionAcknowledged(value) => {
                    runne_plugin_protocol::frame::encode_codec_frame(
                        &SelectionAcknowledgedV2 {
                            host_nonce: value.host_nonce,
                            plugin_nonce: value.plugin_nonce,
                            session_id: value.session_id,
                            profile_id: value.profile_id,
                            profile_digest: value.profile_digest,
                        },
                        &FrameLimits {
                            max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                        },
                    )
                    .unwrap()
                }
                other => encode_frame(
                    &other,
                    &FrameLimits {
                        max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                    },
                )
                .unwrap(),
            };
            inbound[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }
    }
