use runne_plugin_host::{
    ActivationState, PluginActivationId, PluginActivationRequest, PluginAuthorityPort,
    PluginAuthorityRegistry, PluginBootstrapFrame, PluginGenerationPort, PluginGenerationPortError,
    PluginGenerationReadLease, PluginProcessLease, PluginProcessPort, PluginProcessPortError,
    PluginTransportPort, PluginTransportPortError,
};
use runne_plugin_protocol::id::{Nonce, ProtocolSessionId};

const BUILTIN_MANIFEST: &[u8] = b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\nfile_table_digest=sha256:323c9209e107923ed099aa3e8a015ea71cc0c45ea1f3eae041c609bfbd1f5674\nprotocol_profile=builtin-profile-v2|sha256:66e64e0e083bc81b3b8043f9c3aeb306065abb7e0c47456c9f28cdb27e77823a\nfile=entrypoint|executable|39|sha256:c62efb3b0643adea80e7a6eb62c47661b285be4d8c2145b7eb5cfc7d82ba8ceb\nfile=package|data|36|sha256:035f422735e30a22bed0262055206c36fca329f1e2fe2dbad8191a9441fb3572\n";
const BUILTIN_PROFILE: &[u8] = b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\nversion=1.0\nbootstrap_schema_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\nwire_contract_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222\nsession_schema_bundle_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333\nfeatures=bootstrap-v2\nbounds_profile_digest=sha256:4444444444444444444444444444444444444444444444444444444444444444\n";

#[test]
fn public_production_ports_fail_closed_without_certified_constructors() {
    let request = request();
    let snapshot = request.activate(&mut Unavailable, &mut NoTransport, &NoGeneration);
    assert_eq!(snapshot.state(), ActivationState::Verified);
}

fn request() -> PluginActivationRequest {
    let source = runne_plugin_host::PluginPackageCapture::capture(
        runne_plugin_host::PluginPackageContent::try_new(
            b"runne-plugin-host/builtin-package-v1".to_vec(),
            BUILTIN_MANIFEST.to_vec(),
            b"runne-plugin-host/builtin-entrypoint-v1".to_vec(),
            BUILTIN_PROFILE.to_vec(),
            b"runne-plugin-host/builtin-trust-binding-v1".to_vec(),
        )
        .unwrap(),
        runne_plugin_host::PluginClass::Extension,
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
        _: &runne_plugin_host::PluginStartIntent,
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
