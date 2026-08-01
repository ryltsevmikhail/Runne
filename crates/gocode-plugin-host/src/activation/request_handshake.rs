impl PluginActivationRequest {
    fn exchange_host_hello(&self, transport: &mut dyn PluginTransportPort) -> Option<PluginHello> {
        let metadata = self.package.plugin_hello_metadata();
        match self.exchange(
            transport,
            BootstrapMessage::HostHello(HostHello {
                nonce: self.host_nonce,
                host_identity: metadata.host_identity,
                supported_profiles: self.package.advertised_profiles(),
                negotiation_snapshot: self.package.negotiation_snapshot(),
            }),
        )? {
            BootstrapMessage::PluginHello(hello) => Some(hello),
            _ => None,
        }
    }

    fn validate_plugin_hello(&self, hello: &PluginHello) -> Option<Nonce> {
        let metadata = self.package.plugin_hello_metadata();
        let profiles = self.package.advertised_profiles();
        let package_digest = PackageDigest::new(
            DigestAlgorithm::Sha256,
            *self.package.package_digest().as_bytes(),
        );
        if hello.host_nonce != self.host_nonce
            || hello.host_identity != metadata.host_identity
            || hello.package_id != metadata.package_id
            || hello.package_digest != package_digest
            || hello.package_version != metadata.package_version
            || hello.manifest_digest != metadata.manifest_digest
            || hello.plugin_identity != metadata.plugin_identity
            || hello.target_identity != metadata.target_identity
            || hello.entrypoint != metadata.entrypoint
            || hello.supported_profiles != profiles
        {
            return None;
        }
        Some(hello.plugin_nonce)
    }

    fn exchange_profile_selection(
        &self,
        transport: &mut dyn PluginTransportPort,
        plugin_nonce: Nonce,
    ) -> bool {
        let profile = self.protocol_profile();
        let selected = BootstrapMessage::ProfileSelected(ProfileSelected {
            host_nonce: self.host_nonce,
            plugin_nonce,
            session_id: self.session_id,
            profile_id: profile.profile_id().clone(),
            profile_digest: *profile.profile_digest(),
        });
        matches!(self.exchange_v2(transport, selected), Some(SelectionAcknowledgedV2 { host_nonce, plugin_nonce: peer_nonce, session_id, profile_id, profile_digest }) if host_nonce == self.host_nonce && peer_nonce == plugin_nonce && session_id == self.session_id && profile_id == *profile.profile_id() && profile_digest == *profile.profile_digest())
    }

    fn exchange(
        &self,
        transport: &mut dyn PluginTransportPort,
        message: BootstrapMessage,
    ) -> Option<BootstrapMessage> {
        let outbound = encode_frame(
            &message,
            &FrameLimits {
                max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
            },
        )
        .ok()?;
        let mut inbound = [0; MAX_BOOTSTRAP_FRAME_BYTES];
        transport
            .send(PluginBootstrapFrame::outbound(outbound))
            .ok()?;
        let size = transport.receive(&mut inbound).ok()?;
        if size > inbound.len() {
            return None;
        }
        decode_frame(
            &inbound[..size],
            &DecodeLimits {
                max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                ..DecodeLimits::default()
            },
        )
        .ok()
    }

    fn exchange_v2(
        &self,
        transport: &mut dyn PluginTransportPort,
        message: BootstrapMessage,
    ) -> Option<SelectionAcknowledgedV2> {
        let outbound = encode_frame(
            &message,
            &FrameLimits {
                max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
            },
        )
        .ok()?;
        let mut inbound = [0; MAX_BOOTSTRAP_FRAME_BYTES];
        transport
            .send(PluginBootstrapFrame::outbound(outbound))
            .ok()?;
        let size = transport.receive(&mut inbound).ok()?;
        if size > inbound.len() {
            return None;
        }
        decode_codec_frame(
            &inbound[..size],
            &DecodeLimits {
                max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                ..DecodeLimits::default()
            },
        )
        .ok()
    }
}
