#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
use runne_api::{
    ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2,
    ProviderCredentialVerificationKindV2,
};
use serde::Deserialize;

/// Renderer input. There is intentionally no credential or native intent ID.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialIntentIpc {
    pub(crate) provider: ProviderCredentialProviderV2,
    pub(crate) action: ProviderCredentialEnrollmentActionV2,
    pub(crate) expected_revision: u64,
    pub(crate) renderer_generation: u64,
    pub(crate) verification_kind: Option<ProviderCredentialVerificationKindV2>,
}

impl CredentialIntentIpc {
    pub(crate) fn valid(self) -> bool {
        self.expected_revision != 0
            && self.renderer_generation != 0
            && !(matches!(
                self.action,
                ProviderCredentialEnrollmentActionV2::Pair
                    | ProviderCredentialEnrollmentActionV2::MigrateLegacy
            ) && self.verification_kind.is_some())
            && !(self.action == ProviderCredentialEnrollmentActionV2::Revoke
                && self.verification_kind.is_some())
    }

    pub(crate) fn prompt_request(
        self,
    ) -> Result<runne_platform_desktop::SecureCredentialPromptRequest, ()> {
        use runne_platform_desktop::{CredentialPromptAction, CredentialPromptProvider};

        if !self.valid() {
            return Err(());
        }
        let provider = match self.provider {
            ProviderCredentialProviderV2::OpenAi => CredentialPromptProvider::OpenAi,
            ProviderCredentialProviderV2::DeepSeek => CredentialPromptProvider::DeepSeek,
        };
        let action = match self.action {
            ProviderCredentialEnrollmentActionV2::Pair => CredentialPromptAction::Pair,
            ProviderCredentialEnrollmentActionV2::Revoke => CredentialPromptAction::Revoke,
            ProviderCredentialEnrollmentActionV2::MigrateLegacy => {
                CredentialPromptAction::MigrateLegacy
            }
        };
        runne_platform_desktop::SecureCredentialPromptRequest::new(
            provider,
            action,
            self.expected_revision,
        )
        .map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ipc_recursively_rejects_credential_and_renderer_native_intent_id() {
        for value in [
            json!({"provider":"openai","action":"pair","expectedRevision":7,"rendererGeneration":4,"credential":"secret"}),
            json!({"provider":"openai","action":"pair","expectedRevision":7,"rendererGeneration":4,"nativeIntentId":"forged"}),
        ] {
            assert!(serde_json::from_value::<CredentialIntentIpc>(value).is_err());
        }
    }

    #[test]
    fn ipc_requires_a_nonzero_renderer_generation() {
        let zero = serde_json::from_value::<CredentialIntentIpc>(json!({
            "provider":"openai", "action":"pair", "expectedRevision":7, "rendererGeneration":0,
        }))
        .expect("zero generation remains structurally decodable");
        assert!(!zero.valid());
        assert!(
            serde_json::from_value::<CredentialIntentIpc>(json!({
                "provider":"openai", "action":"pair", "expectedRevision":7,
            }))
            .is_err()
        );
    }

    #[test]
    fn ipc_maps_only_closed_public_actions_to_native_prompt_metadata() {
        use runne_platform_desktop::{CredentialPromptAction, CredentialPromptProvider};

        for (action, expected) in [
            (
                ProviderCredentialEnrollmentActionV2::Pair,
                CredentialPromptAction::Pair,
            ),
            (
                ProviderCredentialEnrollmentActionV2::Revoke,
                CredentialPromptAction::Revoke,
            ),
            (
                ProviderCredentialEnrollmentActionV2::MigrateLegacy,
                CredentialPromptAction::MigrateLegacy,
            ),
        ] {
            let request = CredentialIntentIpc {
                provider: ProviderCredentialProviderV2::DeepSeek,
                action,
                expected_revision: 7,
                renderer_generation: 4,
                verification_kind: None,
            };
            let prompt = request.prompt_request().expect("valid prompt request");
            assert_eq!(prompt.provider(), CredentialPromptProvider::DeepSeek);
            assert_eq!(prompt.action(), expected);
            assert_eq!(prompt.expected_revision(), 7);
        }
    }
}
