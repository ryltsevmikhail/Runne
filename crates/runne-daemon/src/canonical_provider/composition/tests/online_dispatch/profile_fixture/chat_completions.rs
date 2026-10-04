use std::sync::Arc;

use runne_provider::ProviderFuture;
use runne_secure_store::ProviderCredentialDispatchMaterializer;

use crate::canonical_provider::CanonicalProviderEffect;
use crate::provider_activation::ProviderActivation;

use super::{FinalSendBarrier, OnlineFixtureMaterializer, PrimaryProfileFixture, SenderFixture};

struct PausedChatTransport {
    barrier: Arc<FinalSendBarrier>,
}

impl runne_daemon_chat_completions_effect::ChatCompletionsTransport for PausedChatTransport {
    fn send(
        &self,
        _: String,
        _: reqwest::header::HeaderName,
        _: reqwest::header::HeaderValue,
        _: Vec<u8>,
        authority: runne_store::provider::ProviderFinalSendAuthority,
    ) -> ProviderFuture<
        '_,
        Result<
            runne_daemon_chat_completions_effect::ChatTransportResponse,
            runne_daemon_chat_completions_effect::ChatTransportError,
        >,
    > {
        let barrier = Arc::clone(&self.barrier);
        Box::pin(async move {
            barrier
                .wait_before_consume(authority)
                .await
                .map_err(|_| runne_daemon_chat_completions_effect::ChatTransportError)?;
            Err(runne_daemon_chat_completions_effect::ChatTransportError)
        })
    }
}

pub(in crate::canonical_provider::composition::tests) fn chat_completions_fixture() -> SenderFixture
{
    let profile = runne_provider_zai::profile();
    let activation = ProviderActivation::from_binding(
        runne_api::ProviderActivationBindingV1::zai_coding_chat_completions_text_v1(),
    );
    let fixture = PrimaryProfileFixture::new(
        activation,
        profile.clone(),
        runne_provider_zai::ZAI_PROVIDER_ID,
        runne_provider_zai::ZAI_MODEL_ID,
        runne_provider_zai::ZAI_MODEL_REVISION,
        "provider.zai.coding.chat_completions.text",
        runne_secure_store::ProviderCredentialId::Zai,
    );
    let barrier = FinalSendBarrier::new();
    let materializer = OnlineFixtureMaterializer::new(runne_provider_zai::ZAI_PROVIDER_ID);
    let erased_materializer: Arc<dyn ProviderCredentialDispatchMaterializer> = materializer.clone();
    let transport = Arc::new(PausedChatTransport {
        barrier: Arc::clone(&barrier),
    });
    let effect: Arc<dyn CanonicalProviderEffect> = Arc::new(
        runne_daemon_chat_completions_effect::ChatCompletionsEffect::new_with_transport(
            profile,
            erased_materializer,
            None,
            runne_daemon_chat_completions_effect::ChatCompletionsAuthHeader::Authorization,
            transport,
        )
        .expect("fixed Z.ai profile and loopback transport construct"),
    );
    super::sender_fixture(fixture, effect, barrier, materializer, true)
}
