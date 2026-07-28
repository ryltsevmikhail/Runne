use gocode_plugin_host::{
    ActivationState, PluginActivationId, PluginActivationRequest, PluginAuthorityPort,
    PluginAuthorityRegistry, PluginBootstrapFrame, PluginGenerationPort, PluginGenerationPortError,
    PluginGenerationReadLease, PluginProcessLease, PluginProcessPort, PluginProcessPortError,
    PluginTransportPort, PluginTransportPortError,
};
use gocode_plugin_protocol::id::{Nonce, ProtocolSessionId};

#[test]
fn public_production_ports_fail_closed_without_certified_constructors() {
    let request = request();
    let snapshot = request.activate(&mut Unavailable, &mut NoTransport, &NoGeneration);
    assert_eq!(snapshot.state(), ActivationState::Verified);
}

fn request() -> PluginActivationRequest {
    let source = gocode_plugin_host::PluginPackageCapture::capture(
        gocode_plugin_host::PluginPackageContent::new(
            b"gocode-plugin-host/builtin-package-v1".to_vec(),
            b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\n".to_vec(),
            b"gocode-plugin-host/builtin-entrypoint-v1".to_vec(),
            b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\n".to_vec(),
            b"gocode-plugin-host/builtin-trust-binding-v1".to_vec(),
        ),
        gocode_plugin_host::PluginClass::Extension,
    );
    let package = PluginAuthorityRegistry::built_in()
        .verifier_for(&source)
        .unwrap()
        .verify(source)
        .unwrap();
    PluginActivationRequest::new(
        package,
        PluginActivationId::new("activation").unwrap(),
        Nonce::from_bytes([1; 16]),
        ProtocolSessionId::from_bytes([7, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]),
    )
}

struct Unavailable;
impl PluginProcessPort for Unavailable {
    fn start(
        &mut self,
        _: &gocode_plugin_host::PluginStartIntent,
        _: &PluginGenerationReadLease,
    ) -> Result<PluginProcessLease, PluginProcessPortError> {
        Err(PluginProcessPortError::BackendUnavailable)
    }
}
struct NoGeneration;
impl PluginGenerationPort for NoGeneration {
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
}
struct NoTransport;
impl PluginTransportPort for NoTransport {
    fn send(&mut self, _: PluginBootstrapFrame) -> Result<(), PluginTransportPortError> {
        Err(PluginTransportPortError::Unavailable)
    }

    fn receive(&mut self, _: &mut [u8]) -> Result<usize, PluginTransportPortError> {
        Err(PluginTransportPortError::Unavailable)
    }
}
