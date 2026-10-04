use std::sync::Arc;

use runne_provider::ProviderFuture;
use runne_secure_store::ProviderCredentialDispatchMaterializer;

use crate::canonical_provider::CanonicalProviderEffect;
use crate::provider_activation::ProviderActivation;

use super::{FinalSendBarrier, OnlineFixtureMaterializer, PrimaryProfileFixture, SenderFixture};

struct PausedNativeTransport {
    barrier: Arc<FinalSendBarrier>,
}

impl runne_daemon_native_effect::NativeTransport for PausedNativeTransport {
    fn send(
        &self,
        _: String,
        _: reqwest::header::HeaderMap,
        _: Vec<u8>,
        authority: runne_store::provider::ProviderFinalSendAuthority,
    ) -> ProviderFuture<
        '_,
        Result<
            runne_daemon_native_effect::NativeTransportResponse,
            runne_daemon_native_effect::NativeTransportError,
        >,
    > {
        let barrier = Arc::clone(&self.barrier);
        Box::pin(async move {
            barrier
                .wait_before_consume(authority)
                .await
                .map_err(|_| runne_daemon_native_effect::NativeTransportError)?;
            Err(runne_daemon_native_effect::NativeTransportError)
        })
    }
}

pub(in crate::canonical_provider::composition::tests) fn native_fixture() -> SenderFixture {
    let binding = runne_api::ProviderActivationBindingV1::new(
        runne_api::ProviderActivationModeV1::NativeTextV1,
        runne_api::NATIVE_ANTHROPIC_PROFILE_ID,
        runne_api::NATIVE_ANTHROPIC_PROFILE_DIGEST,
    )
    .unwrap();
    let (profile, endpoint, auth) =
        crate::application::native_profile_for_fixture(&binding).unwrap();
    let activation = ProviderActivation::from_binding(binding);
    let fixture = PrimaryProfileFixture::new(
        activation,
        profile.clone(),
        profile.provider_id(),
        profile.model_id(),
        profile.model_revision(),
        "provider.native.text",
        runne_secure_store::ProviderCredentialId::Generic("anthropic"),
    );
    let barrier = FinalSendBarrier::new();
    let materializer = OnlineFixtureMaterializer::new("anthropic");
    let erased_materializer: Arc<dyn ProviderCredentialDispatchMaterializer> = materializer.clone();
    let transport = Arc::new(PausedNativeTransport {
        barrier: Arc::clone(&barrier),
    });
    let effect: Arc<dyn CanonicalProviderEffect> =
        runne_daemon_native_effect::NativeEffect::new_with_transport(
            profile,
            endpoint,
            auth,
            erased_materializer,
            Default::default(),
            transport,
        )
        .expect("trusted Anthropic profile and loopback transport construct");
    super::sender_fixture(fixture, effect, barrier, materializer, true)
}
