use crate::provider_activation::ProviderActivation;
use runne_api::{
    ProviderActivationBindingV1, ProviderActivationModeV1, ProviderActivationReadinessV1,
    ProviderReadinessStatusV1, ProviderStatusSnapshotV1,
};

pub(super) fn provider_statuses(
    activation: &ProviderActivation,
    readiness: ProviderActivationReadinessV1,
) -> Vec<ProviderStatusSnapshotV1> {
    let known = [
        (
            "deterministic",
            ProviderActivationBindingV1::deterministic_v1(),
        ),
        (
            "openai",
            ProviderActivationBindingV1::openai_responses_text_v1(),
        ),
        (
            "deepseek",
            ProviderActivationBindingV1::deepseek_responses_text_v1(),
        ),
    ];
    let mut statuses: Vec<_> = known
        .into_iter()
        .map(|(provider_id, binding)| {
            let selected = binding == *activation.binding();
            let readiness = if selected {
                selected_readiness(binding.mode(), readiness)
            } else {
                ProviderReadinessStatusV1::NotSelected
            };
            ProviderStatusSnapshotV1::new(
                provider_id,
                binding.mode().as_str(),
                binding.profile_id(),
                *binding.profile_digest(),
                readiness,
                selected,
            )
            .expect("released provider activation metadata is valid")
        })
        .collect();
    let selected_binding = activation.binding();
    if !statuses
        .iter()
        .any(|status| status.provider_id() == selected_provider_id(activation))
    {
        statuses.push(
            ProviderStatusSnapshotV1::new(
                selected_provider_id(activation),
                selected_binding.mode().as_str(),
                selected_binding.profile_id(),
                *selected_binding.profile_digest(),
                selected_readiness(selected_binding.mode(), readiness),
                true,
            )
            .expect("selected provider activation metadata is valid"),
        );
    }
    statuses
}

fn selected_provider_id(activation: &ProviderActivation) -> String {
    match activation {
        ProviderActivation::ResponsesText(binding, _) => {
            if binding.profile_id().contains("openai-codex") {
                "openai-codex".to_owned()
            } else if binding.profile_id().contains("github-copilot") {
                "github-copilot".to_owned()
            } else if binding.profile_id().contains("azure-openai-responses") {
                "azure-openai-responses".to_owned()
            } else {
                "xai".to_owned()
            }
        }
        ProviderActivation::CloudText(binding, _) => binding
            .profile_id()
            .strip_prefix("gocode-cloud/")
            .and_then(|value| value.split('/').next())
            .unwrap_or("cloud")
            .to_owned(),
        ProviderActivation::ZaiCodingChatCompletionsText(_) => "zai".to_owned(),
        ProviderActivation::QwenCloudTokenChatCompletionsText(_) => {
            "qwen-token-plan-individual".to_owned()
        }
        ProviderActivation::GenericChatCompletionsText(binding) => binding
            .profile_id()
            .strip_prefix("gocode-chat-completions/")
            .and_then(|value| value.split('/').next())
            .unwrap_or("generic")
            .to_owned(),
        ProviderActivation::NativeText(binding, _) => binding
            .profile_id()
            .strip_prefix("gocode-native/")
            .and_then(|value| value.split('/').next())
            .unwrap_or("native")
            .to_owned(),
        ProviderActivation::RadiusText(_, _) => "radius".to_owned(),
        ProviderActivation::LocalEngineText(_) => "local".to_owned(),
        ProviderActivation::OpenAiResponsesText(_) => "openai".to_owned(),
        ProviderActivation::DeepSeekResponsesText(_) => "deepseek".to_owned(),
        ProviderActivation::Deterministic(_) => "deterministic".to_owned(),
    }
}

fn selected_readiness(
    mode: ProviderActivationModeV1,
    readiness: ProviderActivationReadinessV1,
) -> ProviderReadinessStatusV1 {
    if mode == ProviderActivationModeV1::DeterministicV1 {
        return ProviderReadinessStatusV1::Ready;
    }
    match readiness {
        ProviderActivationReadinessV1::Ready => ProviderReadinessStatusV1::Ready,
        ProviderActivationReadinessV1::CredentialMissing => {
            ProviderReadinessStatusV1::CredentialMissing
        }
        ProviderActivationReadinessV1::CredentialAccessDenied => {
            ProviderReadinessStatusV1::CredentialAccessDenied
        }
        ProviderActivationReadinessV1::CredentialIdentityMismatch => {
            ProviderReadinessStatusV1::CredentialIdentityMismatch
        }
        ProviderActivationReadinessV1::SecureStoreUnavailable => {
            ProviderReadinessStatusV1::SecureStoreUnavailable
        }
    }
}
