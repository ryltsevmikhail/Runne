use std::sync::Arc;

use runne_application::ports::ApplicationCommandContext;
use runne_domain::event::Actor;
use runne_domain::id::IdempotencyKey;

use super::super::super::recovery_audit::Harness;
use super::super::profile_fixture::PrimaryProfileFixture;
use super::PausedEffect;
use crate::canonical_provider::OpenAiTextProviderProfile;
use crate::provider_activation::ProviderActivation;

pub(super) async fn compose_paused_openai(
    effect: Arc<PausedEffect>,
) -> (
    Harness,
    Arc<crate::canonical_provider::composition::DaemonCanonicalProviderService>,
) {
    let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .unwrap();
    let fixture = PrimaryProfileFixture::new(
        ProviderActivation::from_binding(
            runne_api::ProviderActivationBindingV1::openai_responses_text_v1(),
        ),
        OpenAiTextProviderProfile::new(profile),
        "openai",
        runne_provider_openai::OPENAI_MODEL_ID,
        runne_provider_openai::OPENAI_MODEL_REVISION,
        "provider.openai.responses.text",
        runne_secure_store::ProviderCredentialId::Generic("openai"),
    );
    let harness = Harness::new_with_profile(&fixture).await;
    let service = harness
        .compose_with_profile(&fixture, effect)
        .await
        .unwrap();
    (harness, service)
}

pub(super) fn test_context(kind: u8, suffix: u8, label: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: uuid7(kind, suffix),
        idempotency_key: IdempotencyKey::new(format!("{label}-{suffix}")).unwrap(),
        principal_id: runne_application::ports::PrincipalId("local-owner".into()),
        actor: Actor::new("final-send-test").unwrap(),
    }
}

fn uuid7<T>(kind: u8, suffix: u8) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    format!("018f2e3a-7000-7000-8000-{kind:02x}{suffix:02x}00000001")
        .parse()
        .unwrap()
}
