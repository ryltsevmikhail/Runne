/// Caller-supplied correlation values plus one registry-verified package.
#[derive(Debug)]
pub struct PluginActivationRequest {
    package: VerifiedPluginPackage,
    activation_id: PluginActivationId,
    host_nonce: Nonce,
    session_id: ProtocolSessionId,
}
