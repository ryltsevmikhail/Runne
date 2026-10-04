use std::sync::Arc;

use runne_provider::ProviderFuture;
use runne_secure_store::ProviderCredentialDispatchMaterializer;

use crate::canonical_provider::CanonicalProviderEffect;
use crate::provider_activation::ProviderActivation;

use super::{FinalSendBarrier, OnlineFixtureMaterializer, PrimaryProfileFixture, SenderFixture};

struct PausedResponsesTransport {
    barrier: Arc<FinalSendBarrier>,
}

impl runne_daemon_responses_effect::ResponsesTransport for PausedResponsesTransport {
    fn send<'a>(
        &'a self,
        _: &'a str,
        _: reqwest::header::HeaderMap,
        _: Vec<u8>,
        authority: runne_store::provider::ProviderFinalSendAuthority,
    ) -> ProviderFuture<
        'a,
        Result<runne_daemon_responses_effect::TransportResponse, runne_provider::DispatchError>,
    > {
        let barrier = Arc::clone(&self.barrier);
        Box::pin(async move {
            barrier.wait_before_consume(authority).await.map_err(|_| {
                runne_provider::DispatchError::RejectedBeforeEffect(
                    runne_provider::ProviderPreEffectRejection::AdapterRejected,
                )
            })?;
            Err(runne_provider::DispatchError::MaybeDispatched)
        })
    }
}

pub(in crate::canonical_provider::composition::tests) fn responses_fixture() -> SenderFixture {
    let profile = runne_provider_responses_wire::codex_subscription_profile(
        runne_provider_responses_wire::CODEX_MAX_OUTPUT_TOKENS,
        runne_provider_responses_wire::CODEX_SUBSCRIPTION_PRICING_DIGEST,
    );
    let binding = runne_api::ProviderActivationBindingV1::new(
        runne_api::ProviderActivationModeV1::ResponsesTextV1,
        profile.profile_id(),
        profile.profile_digest(),
    )
    .unwrap();
    let activation = ProviderActivation::from_binding(binding);
    let fixture = PrimaryProfileFixture::new(
        activation,
        profile.clone(),
        profile.provider_id(),
        profile.model(),
        profile.model_revision(),
        "provider.openai-codex.responses.text",
        runne_secure_store::ProviderCredentialId::Generic("openai-codex"),
    );
    let barrier = FinalSendBarrier::new();
    let materializer = OnlineFixtureMaterializer::new(profile.provider_id());
    let erased_materializer: Arc<dyn ProviderCredentialDispatchMaterializer> = materializer.clone();
    let transport = Arc::new(PausedResponsesTransport {
        barrier: Arc::clone(&barrier),
    });
    let effect = runne_daemon_responses_effect::fixture_effect(
        runne_daemon_responses_effect::ResponsesEffectConfig {
            profile,
            auth: runne_daemon_responses_effect::ResponsesAuth::Codex {
                account_id: "fixture-account".into(),
            },
        },
        erased_materializer,
        transport,
    )
    .expect("fixed Codex profile and loopback transport construct");
    let effect: Arc<dyn CanonicalProviderEffect> =
        crate::canonical_provider::responses_effect_adapter(effect);
    super::sender_fixture(fixture, effect, barrier, materializer, true)
}
