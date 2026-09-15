impl ProviderActivationBindingV1 {
    /// Creates a bounded exact provider activation binding.
    pub fn new(
        mode: ProviderActivationModeV1,
        profile_id: impl Into<String>,
        profile_digest: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        let profile_id = profile_id.into();
        let expected = match mode {
            ProviderActivationModeV1::DeterministicV1 => (
                DETERMINISTIC_PROVIDER_PROFILE_ID,
                DETERMINISTIC_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::OpenAiResponsesTextV1 => (
                OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_ID,
                OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::DeepSeekResponsesTextV1 => (
                DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_ID,
                DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::ZaiCodingChatCompletionsTextV1 => (
                ZAI_CODING_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_ID,
                ZAI_CODING_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::QwenCloudTokenChatCompletionsTextV1 => (
                QWENCLOUD_TOKEN_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_ID,
                QWENCLOUD_TOKEN_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::LocalEngineTextV1 => (
                LOCAL_ENGINE_TEXT_PROVIDER_PROFILE_ID,
                LOCAL_ENGINE_TEXT_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::NativeTextV1 => {
                let expected = match profile_id.as_str() {
                    NATIVE_ANTHROPIC_PROFILE_ID => NATIVE_ANTHROPIC_PROFILE_DIGEST,
                    NATIVE_GOOGLE_PROFILE_ID => NATIVE_GOOGLE_PROFILE_DIGEST,
                    NATIVE_VERTEX_PROFILE_ID => {
                        if profile_digest == [0; 32] {
                            return Err(LaunchAuthorityError::ProviderProfileMismatch);
                        }
                        return Ok(Self {
                            mode,
                            profile_id,
                            profile_digest,
                        });
                    }
                    NATIVE_KIMI_PROFILE_ID => NATIVE_KIMI_PROFILE_DIGEST,
                    NATIVE_MINIMAX_PROFILE_ID | NATIVE_MINIMAX_CN_PROFILE_ID => {
                        if profile_digest == [0; 32] {
                            return Err(LaunchAuthorityError::ProviderProfileMismatch);
                        }
                        return Ok(Self {
                            mode,
                            profile_id,
                            profile_digest,
                        });
                    }
                    NATIVE_VERCEL_PROFILE_ID => NATIVE_VERCEL_PROFILE_DIGEST,
                    _ => return Err(LaunchAuthorityError::ProviderProfileMismatch),
                };
                if profile_digest != expected {
                    return Err(LaunchAuthorityError::ProviderProfileMismatch);
                }
                return Ok(Self {
                    mode,
                    profile_id,
                    profile_digest,
                });
            }
            ProviderActivationModeV1::RadiusTextV1 => {
                if profile_id != RADIUS_TEXT_PROFILE_ID || profile_digest == [0; 32] {
                    return Err(LaunchAuthorityError::ProviderProfileMismatch);
                }
                return Ok(Self {
                    mode,
                    profile_id,
                    profile_digest,
                });
            }
            ProviderActivationModeV1::GenericChatCompletionsTextV1 => {
                if !valid_text(&profile_id, MAX_PROFILE_ID_BYTES)
                    || !profile_id.starts_with("gocode-chat-completions/")
                    || profile_digest == [0; 32]
                {
                    return Err(LaunchAuthorityError::ProviderProfileMismatch);
                }
                return Ok(Self {
                    mode,
                    profile_id,
                    profile_digest,
                });
            }
            ProviderActivationModeV1::ResponsesTextV1 => {
                if !valid_responses_profile_id(&profile_id) || profile_digest == [0; 32] {
                    return Err(LaunchAuthorityError::ProviderProfileMismatch);
                }
                return Ok(Self {
                    mode,
                    profile_id,
                    profile_digest,
                });
            }
            ProviderActivationModeV1::CloudTextV1 => {
                if !valid_cloud_profile_id(&profile_id) || profile_digest == [0; 32] {
                    return Err(LaunchAuthorityError::ProviderProfileMismatch);
                }
                return Ok(Self {
                    mode,
                    profile_id,
                    profile_digest,
                });
            }
        };
        if !valid_text(&profile_id, MAX_PROFILE_ID_BYTES)
            || profile_id != expected.0
            || profile_digest != expected.1
        {
            return Err(LaunchAuthorityError::ProviderProfileMismatch);
        }
        Ok(Self {
            mode,
            profile_id,
            profile_digest,
        })
    }

    /// Returns the released deterministic provider binding.
    #[must_use]
    pub fn deterministic_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::DeterministicV1,
            profile_id: DETERMINISTIC_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: DETERMINISTIC_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the released exact OpenAI Responses text provider binding.
    #[must_use]
    pub fn openai_responses_text_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::OpenAiResponsesTextV1,
            profile_id: OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the released exact DeepSeek Responses text provider binding.
    #[must_use]
    pub fn deepseek_responses_text_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::DeepSeekResponsesTextV1,
            profile_id: DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the released exact Z.ai Coding Plan binding.
    #[must_use]
    pub fn zai_coding_chat_completions_text_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::ZaiCodingChatCompletionsTextV1,
            profile_id: ZAI_CODING_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: ZAI_CODING_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the released exact QwenCloud Token Plan binding.
    #[must_use]
    pub fn qwencloud_token_chat_completions_text_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::QwenCloudTokenChatCompletionsTextV1,
            profile_id: QWENCLOUD_TOKEN_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: QWENCLOUD_TOKEN_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the exact activation mode.
    #[must_use]
    pub const fn mode(&self) -> ProviderActivationModeV1 {
        self.mode
    }

    /// Returns the exact immutable provider profile identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the exact immutable provider profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }

    fn verify_exact(&self, expected: &Self) -> Result<(), LaunchAuthorityError> {
        if self.mode != expected.mode {
            return Err(LaunchAuthorityError::ProviderModeMismatch);
        }
        if self.profile_id != expected.profile_id || self.profile_digest != expected.profile_digest
        {
            return Err(LaunchAuthorityError::ProviderProfileMismatch);
        }
        Ok(())
    }
}

fn valid_responses_profile_id(value: &str) -> bool {
    let mut parts = value.split('/');
    let prefix = parts.next();
    let provider = parts.next();
    let model = parts.next();
    let revision = parts.next();
    prefix == Some("gocode-responses")
        && matches!(
            provider,
            Some("openai-codex" | "github-copilot" | "azure-openai-responses" | "xai")
        )
        && model.is_some_and(|item| {
            valid_text(item, MAX_PROFILE_ID_BYTES)
                && item
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        && revision == Some("1")
        && parts.next().is_none()
}

fn valid_cloud_profile_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("gocode-cloud/") else {
        return false;
    };
    let Some(body) = rest.strip_suffix("/1") else {
        return false;
    };
    let Some((provider, model)) = body.split_once('/') else {
        return false;
    };
    matches!(
        provider,
        "amazon-bedrock" | "cloudflare-workers-ai" | "cloudflare-ai-gateway" | "nvidia"
    ) && valid_text(model, MAX_PROFILE_ID_BYTES)
        && model.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
        })
}

include!("binding_recovery.rs");

/// Stable-profile admission mode for one protected launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationDispositionV1 {
    FirstActivation,
    Existing(Box<StableRuntimeBindingV1>),
    ResumeFirstActivation(Box<PendingFirstActivationV1>),
}

impl ActivationDispositionV1 {
    fn expected_stable(&self) -> Option<&StableRuntimeBindingV1> {
        match self {
            Self::FirstActivation => None,
            Self::Existing(stable) => Some(stable.as_ref()),
            Self::ResumeFirstActivation(pending) => Some(pending.stable()),
        }
    }
}

/// Exact non-secret values the daemon must match before consuming authority.
pub struct LaunchAuthorityValidationV1<'a> {
    pub principal_id: &'a str,
    pub profile: &'a ProtectedRuntimeProfileV1,
    pub executable: &'a ExecutableIdentityV1,
}
