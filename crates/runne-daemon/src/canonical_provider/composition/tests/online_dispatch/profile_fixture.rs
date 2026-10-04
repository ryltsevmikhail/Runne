use std::sync::{Arc, atomic::Ordering};

use runne_provider::{
    ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput, TextProviderProfile,
};
use runne_secure_store::ProviderCredentialId;

use super::super::DaemonCanonicalProviderService;
use super::super::recovery_audit::Harness;
use crate::canonical_provider::{CanonicalProviderEffect, SharedTextProviderProfile};
use crate::provider_activation::ProviderActivation;

mod barrier;
mod chat_completions;
mod http_probe;
mod local_engine;
mod native;
mod openai_deepseek;
mod paused_materializer;
mod prepare;
mod radius;
mod responses;

pub(in crate::canonical_provider::composition::tests) use barrier::{
    FinalSendBarrier, OnlineFixtureMaterializer,
};
pub(in crate::canonical_provider::composition::tests) use chat_completions::chat_completions_fixture;
pub(in crate::canonical_provider::composition::tests) use local_engine::{
    assert_cancel_before_local_execution, local_engine_fixture,
};
pub(in crate::canonical_provider::composition::tests) use native::native_fixture;
pub(in crate::canonical_provider::composition::tests) use openai_deepseek::{
    deepseek_foreground_fixture_cancellation_denies_post,
    openai_foreground_fixture_cancellation_denies_post,
};
pub(in crate::canonical_provider::composition::tests) use prepare::{
    assert_cancel_before_send, prepare_primary_with_instance,
};
pub(in crate::canonical_provider::composition::tests) use radius::radius_fixture;
pub(in crate::canonical_provider::composition::tests) use responses::responses_fixture;

pub(in crate::canonical_provider::composition::tests) struct PrimaryProfileFixture {
    pub(in crate::canonical_provider::composition::tests) activation: ProviderActivation,
    pub(in crate::canonical_provider::composition::tests) profile: Arc<SharedTextProviderProfile>,
    pub(in crate::canonical_provider::composition::tests) provider_id: String,
    pub(in crate::canonical_provider::composition::tests) model_id: String,
    pub(in crate::canonical_provider::composition::tests) model_revision: String,
    pub(in crate::canonical_provider::composition::tests) scope: String,
    pub(in crate::canonical_provider::composition::tests) credential_id: ProviderCredentialId,
    pub(in crate::canonical_provider::composition::tests) call: ProviderCall,
}

impl PrimaryProfileFixture {
    pub(super) fn new<P: TextProviderProfile + 'static>(
        activation: ProviderActivation,
        profile: P,
        provider_id: &str,
        model_id: &str,
        model_revision: &str,
        scope: &str,
        credential_id: ProviderCredentialId,
    ) -> Self {
        let digest = profile.profile_digest();
        assert_eq!(activation.binding().profile_digest(), &digest);
        let provider = ProviderId::new(provider_id).unwrap();
        let max_output_tokens = if provider_id == "openai-codex" {
            runne_provider_responses_wire::CODEX_MAX_OUTPUT_TOKENS
        } else {
            32
        };
        let call = ProviderCall::new(
            ProviderCallId::from_bytes([0xA7; 16]),
            runne_provider::ModelRef::new(provider, model_id.to_owned(), model_revision.to_owned())
                .unwrap(),
            [0xB8; 32],
            max_output_tokens,
            profile.call_binding_extension(),
        )
        .unwrap()
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "pre-consume cancellation fixture")
                .unwrap(),
        ])
        .unwrap()
        .with_required_capabilities(vec![ProviderCapability::Streaming]);
        Self {
            activation,
            profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
            provider_id: provider_id.to_owned(),
            model_id: model_id.to_owned(),
            model_revision: model_revision.to_owned(),
            scope: scope.to_owned(),
            credential_id,
            call,
        }
    }
}

pub(in crate::canonical_provider::composition::tests) struct SenderFixture {
    pub(super) profile: PrimaryProfileFixture,
    pub(super) effect: Arc<dyn CanonicalProviderEffect>,
    pub(super) barrier: Arc<FinalSendBarrier>,
    pub(super) materializer: Arc<OnlineFixtureMaterializer>,
    pub(super) materializer_expected: bool,
}

pub(in crate::canonical_provider::composition::tests) fn sender_fixture(
    profile: PrimaryProfileFixture,
    effect: Arc<dyn CanonicalProviderEffect>,
    barrier: Arc<FinalSendBarrier>,
    materializer: Arc<OnlineFixtureMaterializer>,
    materializer_expected: bool,
) -> SenderFixture {
    SenderFixture {
        profile,
        effect,
        barrier,
        materializer,
        materializer_expected,
    }
}

pub(in crate::canonical_provider::composition::tests) fn assert_materializer_called(
    materializer: &OnlineFixtureMaterializer,
) {
    assert_eq!(materializer.calls.load(Ordering::SeqCst), 1);
}

pub(in crate::canonical_provider::composition::tests) async fn build_service(
    profile: &PrimaryProfileFixture,
    effect: Arc<dyn CanonicalProviderEffect>,
) -> (Harness, Arc<DaemonCanonicalProviderService>) {
    let harness = Harness::new_with_profile(profile).await;
    let service = harness.compose_with_profile(profile, effect).await.unwrap();
    (harness, service)
}
