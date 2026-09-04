use std::sync::Arc;

use runne_api::MacOsCodeIdentityExpectationV1;
use runne_macos_xpc::CredentialServiceEndpointRole;
use runne_provider::CredentialWriterAuthorityPair;

use crate::provider_credential::broker::writer::NativeProviderCredentialEffectRoute;

#[test]
fn exact_v3_identity_pair_builds_only_the_writer_service_endpoint() {
    let service = identity("com.runne.credential-service", '4');
    let writer = identity("runne", '2');

    let configuration = super::writer_endpoint_configuration(&service, &writer).unwrap();

    assert_eq!(configuration.role(), CredentialServiceEndpointRole::Writer);
    assert!(super::writer_endpoint_configuration(&service, &service).is_err());
}

#[test]
fn exact_v3_route_never_constructs_the_legacy_native_writer() {
    let service = identity("com.runne.credential-service", '4');
    let writer = identity("runne", '2');
    let configuration = super::writer_endpoint_configuration(&service, &writer).unwrap();
    let (_, effects) = CredentialWriterAuthorityPair::new().split();

    let route = super::build_effect_route(
        effects,
        Some(configuration),
        |_| panic!("tuple V3 must not construct the legacy native writer"),
        || Ok(legacy_source()),
    )
    .unwrap();

    assert!(matches!(
        route,
        NativeProviderCredentialEffectRoute::CredentialService { .. }
    ));
}

fn identity(identifier: &str, cdhash: char) -> MacOsCodeIdentityExpectationV1 {
    MacOsCodeIdentityExpectationV1::new(identifier, "758F9Z45SR", cdhash.to_string().repeat(40))
        .unwrap()
}

fn legacy_source() -> Arc<dyn super::BrokeredProviderCredentialLegacySource> {
    let (_, effects) = CredentialWriterAuthorityPair::new().split();
    let (_, measurements) = runne_provider::CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([8; 32]).unwrap();
    let binding = runne_provider::CredentialBindingDigest::from_measured([9; 32]).unwrap();
    let executable = std::env::current_exe().unwrap();
    let access = crate::ProviderCredentialAccessPolicy::new(&executable, &executable).unwrap();
    Arc::new(super::NativeProviderCredentialLegacySource::new(
        crate::NativeProviderCredentialStore::new(),
        access,
        effects.legacy_read_verifier(binding, &channel),
    ))
}
