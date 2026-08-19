impl PluginActivationRequest {
    /// Creates an activation request. Registry authority owns all profile, metadata and generation choices.
    pub fn new(
        package: VerifiedPluginPackage,
        activation_id: PluginActivationId,
        host_nonce: Nonce,
        session_id: ProtocolSessionId,
    ) -> Self {
        Self {
            package,
            activation_id,
            host_nonce,
            session_id,
        }
    }

    /// Starts the process and performs the registry-bound v2 bootstrap protocol.
    /// Legacy convenience entry point: without durable reservation authority it
    /// intentionally cannot cross the process boundary.
    pub fn activate(
        &self,
        _: &mut dyn PluginProcessPort,
        _: &mut dyn PluginTransportPort,
        _: &dyn PluginGenerationPort,
    ) -> PluginActivationSnapshot {
        PluginActivationSnapshot::pre_start(self, ActivationState::Verified)
    }


}
