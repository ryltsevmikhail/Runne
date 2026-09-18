use super::{ActiveProviderInfo, ProviderActivation};
use runne_provider_deepseek::{DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION};
use runne_provider_openai::{OPENAI_MODEL_ID, OPENAI_MODEL_REVISION};

pub(super) fn active_provider_info(activation: &ProviderActivation) -> Option<ActiveProviderInfo> {
    match activation {
        ProviderActivation::Deterministic(_) => None,
        ProviderActivation::LocalEngineText(binding) => {
            info(activation, binding, "local-engine-text", "v1")
        }
        ProviderActivation::OpenAiResponsesText(binding) => {
            info(activation, binding, OPENAI_MODEL_ID, OPENAI_MODEL_REVISION)
        }
        ProviderActivation::DeepSeekResponsesText(binding) => info(
            activation,
            binding,
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        ),
        ProviderActivation::ZaiCodingChatCompletionsText(binding) => info(
            activation,
            binding,
            runne_provider_zai::ZAI_MODEL_ID,
            runne_provider_zai::ZAI_MODEL_REVISION,
        ),
        ProviderActivation::QwenCloudTokenChatCompletionsText(binding) => info(
            activation,
            binding,
            runne_provider_qwencloud::QWENCLOUD_MODEL_ID,
            runne_provider_qwencloud::QWENCLOUD_MODEL_REVISION,
        ),
        ProviderActivation::GenericChatCompletionsText(binding) => {
            let profile = runne_provider_chat_completions::generic_profiles()
                .iter()
                .find(|profile| profile.profile_id == binding.profile_id());
            Some(ActiveProviderInfo {
                activation: activation.clone(),
                profile_id: binding.profile_id().to_owned(),
                model_id: profile.map_or_else(
                    || "unknown".to_owned(),
                    |item| item.profile.model_id().to_owned(),
                ),
                model_revision: profile.map_or_else(
                    || "unknown".to_owned(),
                    |item| item.profile.model_revision().to_owned(),
                ),
            })
        }
        ProviderActivation::NativeText(binding, _) => {
            let model = if binding.profile_id() == runne_api::NATIVE_ANTHROPIC_PROFILE_ID {
                "claude-sonnet-4-6"
            } else if binding.profile_id() == runne_api::NATIVE_GOOGLE_PROFILE_ID
                || binding.profile_id() == runne_api::NATIVE_VERTEX_PROFILE_ID
            {
                "gemini-2.5-flash"
            } else if binding.profile_id() == runne_api::NATIVE_KIMI_PROFILE_ID {
                "k3-256k"
            } else if binding.profile_id() == runne_api::NATIVE_VERCEL_PROFILE_ID {
                "openai/gpt-5.6-luna"
            } else {
                "MiniMax-M2.7"
            };
            info(activation, binding, model, "pi-0.85.1")
        }
        ProviderActivation::RadiusText(binding, settings) => info(
            activation,
            binding,
            settings.radius_model_id.as_deref().unwrap_or("dynamic"),
            settings.radius_revision.as_deref().unwrap_or("dynamic"),
        ),
        ProviderActivation::ResponsesText(binding, _) => {
            let model = profile_model(binding.profile_id(), "gocode-responses/");
            info(
                activation,
                binding,
                model.as_deref().unwrap_or("configured"),
                "pi/71dca871bc80b6bc97be37f0ca3189399d651fff",
            )
        }
        ProviderActivation::CloudText(binding, _) => {
            let model = profile_model(binding.profile_id(), "gocode-cloud/");
            info(
                activation,
                binding,
                model.as_deref().unwrap_or("configured"),
                "cloud-v1",
            )
        }
    }
}

fn info(
    activation: &ProviderActivation,
    binding: &runne_api::ProviderActivationBindingV1,
    model_id: &str,
    model_revision: &str,
) -> Option<ActiveProviderInfo> {
    Some(ActiveProviderInfo {
        activation: activation.clone(),
        profile_id: binding.profile_id().to_owned(),
        model_id: model_id.to_owned(),
        model_revision: model_revision.to_owned(),
    })
}

fn profile_model(profile_id: &str, prefix: &str) -> Option<String> {
    profile_id
        .strip_prefix(prefix)?
        .strip_suffix("/1")?
        .split_once('/')
        .map(|(_, model)| model.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};

    #[test]
    fn configured_nested_models_are_reported_without_flattening() {
        let responses = ProviderActivation::from_binding(
            ProviderActivationBindingV1::new(
                ProviderActivationModeV1::ResponsesTextV1,
                "gocode-responses/azure-openai-responses/o3-mini/1",
                [1; 32],
            )
            .unwrap(),
        );
        let info = active_provider_info(&responses).unwrap();
        assert_eq!(info.model_id, "o3-mini");

        let cloud = ProviderActivation::from_binding(
            ProviderActivationBindingV1::new(
                ProviderActivationModeV1::CloudTextV1,
                "gocode-cloud/cloudflare-workers-ai/@cf/meta/llama-3.1-8b-instruct/1",
                [2; 32],
            )
            .unwrap(),
        );
        let info = active_provider_info(&cloud).unwrap();
        assert_eq!(info.model_id, "@cf/meta/llama-3.1-8b-instruct");
    }
}
