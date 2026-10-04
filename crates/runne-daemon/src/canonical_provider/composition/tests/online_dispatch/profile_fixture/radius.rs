use std::sync::Arc;

use runne_provider::ProviderFuture;
use runne_secure_store::ProviderCredentialDispatchMaterializer;

use crate::canonical_provider::CanonicalProviderEffect;
use crate::provider_activation::ProviderActivation;

use super::{FinalSendBarrier, OnlineFixtureMaterializer, PrimaryProfileFixture, SenderFixture};

struct PausedRadiusTransport {
    barrier: Arc<FinalSendBarrier>,
}

impl runne_daemon_radius_effect::RadiusTransport for PausedRadiusTransport {
    fn send(
        &self,
        _: String,
        _: reqwest::header::HeaderMap,
        _: Vec<u8>,
        authority: runne_store::provider::ProviderFinalSendAuthority,
    ) -> ProviderFuture<
        '_,
        Result<
            runne_daemon_radius_effect::RadiusTransportResponse,
            runne_daemon_radius_effect::RadiusTransportError,
        >,
    > {
        let barrier = Arc::clone(&self.barrier);
        Box::pin(async move {
            barrier
                .wait_before_consume(authority)
                .await
                .map_err(|_| runne_daemon_radius_effect::RadiusTransportError)?;
            Err(runne_daemon_radius_effect::RadiusTransportError)
        })
    }
}

pub(in crate::canonical_provider::composition::tests) fn radius_fixture() -> SenderFixture {
    let catalog_bytes = br#"{"baseUrl":"https://radius.pi.dev","models":[{"id":"dynamic-model","name":"Dynamic","reasoning":false,"input":["text"],"cost":{"input":1,"output":2,"cacheRead":0.1,"cacheWrite":0},"contextWindow":8192,"maxTokens":1024}]}"#;
    let profile = runne_provider_radius::RadiusCatalog::from_json_at(
        catalog_bytes,
        runne_provider_radius::DEFAULT_RADIUS_GATEWAY,
    )
    .unwrap()
    .select_with_accounting(
        "radius",
        "dynamic-model",
        "catalog-rev",
        runne_provider_radius::RadiusAccounting::SubscriptionQuota,
    )
    .unwrap();
    let binding = runne_api::ProviderActivationBindingV1::new(
        runne_api::ProviderActivationModeV1::RadiusTextV1,
        runne_api::RADIUS_TEXT_PROFILE_ID,
        profile.profile_digest(),
    )
    .unwrap();
    let activation = ProviderActivation::from_binding(binding);
    let fixture = PrimaryProfileFixture::new(
        activation,
        profile.clone(),
        "radius",
        "dynamic-model",
        "catalog-rev",
        "provider.radius.text",
        runne_secure_store::ProviderCredentialId::Generic("radius"),
    );
    let barrier = FinalSendBarrier::new();
    let materializer = OnlineFixtureMaterializer::new("radius");
    let erased_materializer: Arc<dyn ProviderCredentialDispatchMaterializer> = materializer.clone();
    let transport = Arc::new(PausedRadiusTransport {
        barrier: Arc::clone(&barrier),
    });
    let effect: Arc<dyn CanonicalProviderEffect> =
        runne_daemon_radius_effect::RadiusEffect::new_with_transport(
            profile,
            runne_daemon_radius_effect::RadiusAuth::ApiKey,
            erased_materializer,
            Default::default(),
            transport,
        )
        .expect("pinned Radius profile and loopback transport construct");
    super::sender_fixture(fixture, effect, barrier, materializer, true)
}
