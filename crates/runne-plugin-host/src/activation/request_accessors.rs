impl PluginActivationRequest {
    pub const fn host_nonce(&self) -> Nonce {
        self.host_nonce
    }
    pub const fn session_id(&self) -> ProtocolSessionId {
        self.session_id
    }
    pub const fn generation(&self) -> PluginGeneration {
        self.package.generation()
    }
    pub fn protocol_profile(&self) -> runne_plugin_protocol::profile::ProtocolProfileRef {
        self.package.selected_profile()
    }
    pub const fn package_digest(&self) -> PluginDigest {
        self.package.package_digest()
    }


}
