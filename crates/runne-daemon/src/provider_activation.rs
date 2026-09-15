//! Exact provider-mode activation selected before daemon readiness.

use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};

pub(crate) mod cloud;
pub(crate) mod responses;
mod settings;
pub(crate) use responses::configured_profile;
pub(crate) use settings::{ProviderAccountingMode, ProviderActivationSettings};

/// Validated non-secret provider activation retained by the daemon composition root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderActivation {
    /// Credential-free deterministic compatibility mode.
    Deterministic(ProviderActivationBindingV1),
    /// Exact OpenAI Responses text mode. Execution wiring is admitted separately.
    OpenAiResponsesText(ProviderActivationBindingV1),
    /// Exact DeepSeek Responses text mode. Execution wiring is admitted separately.
    DeepSeekResponsesText(ProviderActivationBindingV1),
    /// Exact Z.ai Coding Plan Chat Completions activation.
    ZaiCodingChatCompletionsText(ProviderActivationBindingV1),
    /// Exact QwenCloud Token Plan Chat Completions activation.
    QwenCloudTokenChatCompletionsText(ProviderActivationBindingV1),
    /// Exact catalog-backed Chat Completions text mode.
    GenericChatCompletionsText(ProviderActivationBindingV1),
    /// Exact bounded Local Engine text mode. Execution wiring is admitted separately.
    LocalEngineText(ProviderActivationBindingV1),
    /// Exact native Anthropic/Gemini-family text mode.
    NativeText(ProviderActivationBindingV1, ProviderActivationSettings),
    /// Exact catalog-bound Radius text mode.
    RadiusText(ProviderActivationBindingV1, ProviderActivationSettings),
    /// Exact closed-registry Responses text mode for four supported providers.
    ResponsesText(ProviderActivationBindingV1, ProviderActivationSettings),
    /// Reserved closed-registry cloud mode; provider-specific settings are
    /// admitted only when the cloud effect owns their exact profile.
    CloudText(ProviderActivationBindingV1, ProviderActivationSettings),
}

impl ProviderActivation {
    /// Returns the V1 deterministic compatibility activation.
    #[must_use]
    pub fn deterministic_v1() -> Self {
        Self::Deterministic(ProviderActivationBindingV1::deterministic_v1())
    }

    /// Classifies an already exact, decoded protocol V2 binding.
    #[must_use]
    pub fn from_binding(binding: ProviderActivationBindingV1) -> Self {
        Self::from_binding_with_settings(binding, ProviderActivationSettings::default())
    }

    /// Classifies a binding together with validated non-secret settings.
    #[must_use]
    pub fn from_binding_with_settings(
        binding: ProviderActivationBindingV1,
        settings: ProviderActivationSettings,
    ) -> Self {
        match binding.mode() {
            ProviderActivationModeV1::DeterministicV1 => Self::Deterministic(binding),
            ProviderActivationModeV1::OpenAiResponsesTextV1 => Self::OpenAiResponsesText(binding),
            ProviderActivationModeV1::DeepSeekResponsesTextV1 => {
                Self::DeepSeekResponsesText(binding)
            }
            ProviderActivationModeV1::ZaiCodingChatCompletionsTextV1 => {
                Self::ZaiCodingChatCompletionsText(binding)
            }
            ProviderActivationModeV1::QwenCloudTokenChatCompletionsTextV1 => {
                Self::QwenCloudTokenChatCompletionsText(binding)
            }
            ProviderActivationModeV1::GenericChatCompletionsTextV1 => {
                Self::GenericChatCompletionsText(binding)
            }
            ProviderActivationModeV1::LocalEngineTextV1 => Self::LocalEngineText(binding),
            ProviderActivationModeV1::NativeTextV1 => Self::NativeText(binding, settings),
            ProviderActivationModeV1::RadiusTextV1 => Self::RadiusText(binding, settings),
            ProviderActivationModeV1::ResponsesTextV1 => Self::ResponsesText(binding, settings),
            ProviderActivationModeV1::CloudTextV1 => Self::CloudText(binding, settings),
        }
    }

    pub(crate) fn validate_settings(
        mode: ProviderActivationModeV1,
        profile_id: &str,
        settings: &ProviderActivationSettings,
    ) -> Result<(), &'static str> {
        let has_vertex = settings.vertex_project.is_some() || settings.vertex_location.is_some();
        let has_radius = settings.radius_catalog.is_some()
            || settings.radius_model_id.is_some()
            || settings.radius_revision.is_some();
        let has_responses = settings.responses_resource.is_some()
            || settings.responses_deployment.is_some()
            || settings.responses_pricing_digest.is_some()
            || settings.responses_input_micros_per_million.is_some()
            || settings.responses_output_micros_per_million.is_some()
            || settings.responses_cached_input_micros_per_million.is_some()
            || settings.responses_max_output_tokens.is_some()
            || settings.responses_context_tokens.is_some();
        let has_cloud = settings.cloud_region_or_account.is_some()
            || settings.cloud_gateway.is_some()
            || settings.cloud_input_micros_per_million.is_some()
            || settings.cloud_output_micros_per_million.is_some()
            || settings.cloud_cached_input_micros_per_million.is_some()
            || settings.cloud_context_tokens.is_some()
            || settings.cloud_max_output_tokens.is_some()
            || settings.cloud_max_model_output_tokens.is_some()
            || settings.cloud_max_input_entries.is_some()
            || settings.cloud_max_input_entry_bytes.is_some()
            || settings.cloud_max_input_bytes.is_some()
            || settings.cloud_max_request_bytes.is_some()
            || settings.cloud_max_response_frame_bytes.is_some()
            || settings.cloud_gateway_billing.is_some();
        match mode {
            ProviderActivationModeV1::NativeTextV1 => {
                if has_radius {
                    return Err("Radius settings are not valid for native provider");
                }
                let vertex = profile_id == runne_api::NATIVE_VERTEX_PROFILE_ID;
                if vertex != has_vertex {
                    return Err("Vertex settings do not match selected native provider");
                }
                if vertex && settings.accounting_mode.is_some() {
                    return Err("Vertex accounting mode is fixed by its trusted profile");
                }
                let minimax = profile_id == runne_api::NATIVE_MINIMAX_PROFILE_ID
                    || profile_id == runne_api::NATIVE_MINIMAX_CN_PROFILE_ID;
                if minimax && settings.accounting_mode.is_none() {
                    return Err("MiniMax accounting mode must be explicit");
                }
                if !minimax && settings.accounting_mode.is_some() {
                    return Err("Accounting mode is not valid for selected native provider");
                }
            }
            ProviderActivationModeV1::RadiusTextV1 => {
                if has_vertex
                    || settings.radius_catalog.is_none()
                    || settings.radius_model_id.is_none()
                    || settings.radius_revision.is_none()
                {
                    return Err("Radius settings are incomplete or mixed with Vertex settings");
                }
            }
            ProviderActivationModeV1::ResponsesTextV1 => {
                if has_vertex
                    || has_radius
                    || has_cloud
                    || settings
                        .accounting_mode
                        .is_some_and(|mode| !matches!(mode, ProviderAccountingMode::Payg))
                {
                    return Err("Responses settings are mixed with another provider family");
                }
                if profile_id.contains("azure-openai-responses")
                    && (!has_responses
                        || settings.responses_context_tokens.is_none()
                        || settings.responses_max_output_tokens.is_none())
                {
                    return Err("Azure Responses settings are required");
                }
            }
            ProviderActivationModeV1::CloudTextV1 => {
                if has_vertex || has_radius || has_responses {
                    return Err("Cloud settings are mixed with another provider family");
                }
                cloud::configured_profile(profile_id, settings)
                    .map(|_| ())
                    .map_err(|message| message)?;
            }
            _ if has_vertex
                || has_radius
                || has_responses
                || has_cloud
                || settings.accounting_mode.is_some() =>
            {
                return Err("provider settings are inappropriate for selected mode");
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns the exact non-secret mode/profile binding.
    #[must_use]
    pub const fn binding(&self) -> &ProviderActivationBindingV1 {
        match self {
            Self::Deterministic(binding)
            | Self::OpenAiResponsesText(binding)
            | Self::DeepSeekResponsesText(binding)
            | Self::ZaiCodingChatCompletionsText(binding)
            | Self::QwenCloudTokenChatCompletionsText(binding)
            | Self::GenericChatCompletionsText(binding)
            | Self::LocalEngineText(binding)
            | Self::NativeText(binding, _)
            | Self::RadiusText(binding, _) => binding,
            Self::ResponsesText(binding, _) | Self::CloudText(binding, _) => binding,
        }
    }

    /// Reports whether the exact OpenAI execution path is required.
    #[must_use]
    pub const fn requires_openai_execution(&self) -> bool {
        matches!(self, Self::OpenAiResponsesText(_))
    }

    /// Reports whether the exact DeepSeek execution path is required.
    #[must_use]
    pub const fn requires_deepseek_execution(&self) -> bool {
        matches!(self, Self::DeepSeekResponsesText(_))
    }

    /// Reports whether exact Z.ai Coding Plan execution is required.
    #[must_use]
    pub const fn requires_zai_coding_execution(&self) -> bool {
        matches!(self, Self::ZaiCodingChatCompletionsText(_))
    }

    /// Reports whether exact QwenCloud Token Plan execution is required.
    #[must_use]
    pub const fn requires_qwencloud_execution(&self) -> bool {
        matches!(self, Self::QwenCloudTokenChatCompletionsText(_))
    }

    /// Reports whether the exact Local Engine execution path is required.
    #[must_use]
    pub const fn requires_local_engine_execution(&self) -> bool {
        matches!(self, Self::LocalEngineText(_))
    }

    /// Reports whether a native provider effect is required.
    #[must_use]
    pub const fn requires_native_execution(&self) -> bool {
        matches!(self, Self::NativeText(..))
    }

    /// Reports whether the dynamic Radius effect is required.
    #[must_use]
    pub const fn requires_radius_execution(&self) -> bool {
        matches!(self, Self::RadiusText(..))
    }

    /// Reports whether one of the Chat Completions routes is required.
    #[must_use]
    pub const fn requires_chat_completions_execution(&self) -> bool {
        matches!(
            self,
            Self::ZaiCodingChatCompletionsText(_)
                | Self::QwenCloudTokenChatCompletionsText(_)
                | Self::GenericChatCompletionsText(_)
        )
    }

    /// Reports whether a closed-registry Responses effect is required.
    #[must_use]
    pub const fn requires_responses_execution(&self) -> bool {
        matches!(self, Self::ResponsesText(..))
    }

    /// Reports whether the reserved cloud execution path is selected.
    #[must_use]
    pub const fn requires_cloud_execution(&self) -> bool {
        matches!(self, Self::CloudText(..))
    }

    /// Returns dynamic non-secret settings, if the mode carries them.
    #[must_use]
    pub fn settings(&self) -> Option<&ProviderActivationSettings> {
        match self {
            Self::NativeText(_, settings)
            | Self::RadiusText(_, settings)
            | Self::ResponsesText(_, settings)
            | Self::CloudText(_, settings) => Some(settings),
            _ => None,
        }
    }
}
