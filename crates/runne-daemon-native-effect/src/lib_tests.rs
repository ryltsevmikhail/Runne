use std::sync::Arc;

use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};

use super::*;

struct DenyingMaterializer;
impl ProviderCredentialDispatchMaterializer for DenyingMaterializer {
    fn materialize_active(
        &self,
        _: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        Err(SecureStoreError::CredentialAccessDenied)
    }
}

fn profile() -> NativeWireProfile {
    NativeWireProfile::Anthropic(
        runne_provider_native_wire::AnthropicMessagesProfile::new(
            "anthropic",
            "native/1",
            "model",
            "rev",
            [1; 32],
            [2; 32],
            runne_provider_native_wire::WireLimits::new(4, 128, 512, 128, 4096, 2048).unwrap(),
        )
        .unwrap(),
    )
}

#[test]
fn constructor_rejects_route_query_and_protocol_auth_mismatch() {
    assert_eq!(
        TrustedNativeEndpoint::anthropic("https://example.test/?key=bad"),
        Err(NativeEffectError::UnsafeEndpoint)
    );
    assert_eq!(
        TrustedNativeEndpoint::anthropic("http://127.0.0.1:8080"),
        Err(NativeEffectError::UnsafeEndpoint)
    );
    let endpoint = TrustedNativeEndpoint::gemini("https://example.test").unwrap();
    assert!(matches!(
        NativeEffect::new(
            profile(),
            endpoint,
            NativeAuthDescriptor::GeminiApiKey,
            Arc::new(DenyingMaterializer),
            NativeEffectConfig::default()
        ),
        Err(NativeEffectError::AuthMismatch)
    ));
    assert!(matches!(
        NativeEffect::new(
            profile(),
            TrustedNativeEndpoint::anthropic("https://evil.example").unwrap(),
            NativeAuthDescriptor::AnthropicApiKey,
            Arc::new(DenyingMaterializer),
            NativeEffectConfig::default()
        ),
        Err(NativeEffectError::AuthMismatch)
    ));
}
