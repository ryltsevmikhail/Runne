#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
use runne_api::{ProviderCredentialProviderV2, ProviderCredentialVerificationKindV2};
use serde::Deserialize;

/// Closed native intent actions. Verify is separate from enrollment mutation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialIntentAction {
    Pair,
    Revoke,
    MigrateLegacy,
    Verify,
}

/// Renderer input. There is intentionally no credential or native intent ID.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialIntentIpc {
    pub(crate) provider: ProviderCredentialProviderV2,
    pub(crate) action: CredentialIntentAction,
    pub(crate) expected_revision: u64,
    pub(crate) renderer_generation: u64,
    pub(crate) verification_kind: Option<ProviderCredentialVerificationKindV2>,
}

impl CredentialIntentIpc {
    pub(crate) const fn supported_enrollment_action(self) -> bool {
        matches!(
            self.action,
            CredentialIntentAction::Pair | CredentialIntentAction::Revoke
        )
    }

    pub(crate) const fn supported_verification_action(self) -> bool {
        matches!(
            (self.action, self.verification_kind),
            (
                CredentialIntentAction::Verify,
                Some(ProviderCredentialVerificationKindV2::Remote)
            )
        )
    }

    pub(crate) const fn is_verification(self) -> bool {
        matches!(self.action, CredentialIntentAction::Verify)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) const fn writer_handoff_mode(
        self,
    ) -> runne_platform_desktop::CredentialWriterHandoffMode {
        match self.action {
            CredentialIntentAction::Pair => {
                runne_platform_desktop::CredentialWriterHandoffMode::Pair
            }
            CredentialIntentAction::Revoke
            | CredentialIntentAction::MigrateLegacy
            | CredentialIntentAction::Verify => {
                runne_platform_desktop::CredentialWriterHandoffMode::ControlOnly
            }
        }
    }

    pub(crate) fn valid(self) -> bool {
        self.expected_revision != 0
            && self.renderer_generation != 0
            && match self.action {
                CredentialIntentAction::Verify => self.supported_verification_action(),
                CredentialIntentAction::Pair
                | CredentialIntentAction::Revoke
                | CredentialIntentAction::MigrateLegacy => self.verification_kind.is_none(),
            }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn prompt_request(
        self,
    ) -> Result<runne_platform_desktop::SecureCredentialPromptRequest, ()> {
        use runne_platform_desktop::{
            CredentialPromptAction, CredentialPromptCatalogId, CredentialPromptProvider,
        };

        if !self.valid() {
            return Err(());
        }
        let provider = match self.provider {
            ProviderCredentialProviderV2::OpenAi => CredentialPromptProvider::OpenAi,
            ProviderCredentialProviderV2::DeepSeek => CredentialPromptProvider::DeepSeek,
            provider => CredentialPromptProvider::Catalog(
                CredentialPromptCatalogId::parse(provider.as_str()).ok_or(())?,
            ),
        };
        let action = match self.action {
            CredentialIntentAction::Pair => CredentialPromptAction::Pair,
            CredentialIntentAction::Revoke => CredentialPromptAction::Revoke,
            CredentialIntentAction::MigrateLegacy => CredentialPromptAction::MigrateLegacy,
            CredentialIntentAction::Verify => CredentialPromptAction::Verify,
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn ipc_maps_only_closed_public_actions_to_native_prompt_metadata() {
        use runne_platform_desktop::{CredentialPromptAction, CredentialPromptProvider};

        for (action, expected) in [
            (CredentialIntentAction::Pair, CredentialPromptAction::Pair),
            (
                CredentialIntentAction::Revoke,
                CredentialPromptAction::Revoke,
            ),
            (
                CredentialIntentAction::MigrateLegacy,
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn only_pair_selects_the_native_secret_relay_handoff() {
        use runne_platform_desktop::CredentialWriterHandoffMode;

        for (action, expected) in [
            (
                CredentialIntentAction::Pair,
                CredentialWriterHandoffMode::Pair,
            ),
            (
                CredentialIntentAction::Revoke,
                CredentialWriterHandoffMode::ControlOnly,
            ),
            (
                CredentialIntentAction::MigrateLegacy,
                CredentialWriterHandoffMode::ControlOnly,
            ),
        ] {
            let request = CredentialIntentIpc {
                provider: ProviderCredentialProviderV2::OpenAi,
                action,
                expected_revision: 7,
                renderer_generation: 4,
                verification_kind: None,
            };
            assert_eq!(request.writer_handoff_mode(), expected);
        }
    }

    #[test]
    fn action_gate_allows_pair_and_revoke_for_both_closed_providers() {
        for provider in [
            ProviderCredentialProviderV2::OpenAi,
            ProviderCredentialProviderV2::DeepSeek,
        ] {
            for action in [CredentialIntentAction::Pair, CredentialIntentAction::Revoke] {
                assert!(
                    CredentialIntentIpc {
                        provider,
                        action,
                        expected_revision: 7,
                        renderer_generation: 4,
                        verification_kind: None,
                    }
                    .supported_enrollment_action()
                );
            }
        }
        assert!(
            !CredentialIntentIpc {
                provider: ProviderCredentialProviderV2::OpenAi,
                action: CredentialIntentAction::MigrateLegacy,
                expected_revision: 7,
                renderer_generation: 4,
                verification_kind: None,
            }
            .supported_enrollment_action()
        );
    }

    #[test]
    fn action_gate_precedes_prompt_transition_and_writer() {
        let source = include_str!("dispatch.rs");
        let gate = source.find("run_after_action_gate(request").unwrap();
        for later in [
            "prepare_installed_native_enrollment",
            "prompt.prompt",
            "transition_and_install",
            "exchange.run",
        ] {
            assert!(
                gate < source.find(later).unwrap(),
                "gate must precede {later}"
            );
        }
    }

    #[test]
    fn invalid_or_unsupported_action_gate_invokes_no_native_work() {
        let prompt = std::cell::Cell::new(0);
        let spawn = std::cell::Cell::new(0);
        let request = CredentialIntentIpc {
            provider: ProviderCredentialProviderV2::OpenAi,
            action: CredentialIntentAction::MigrateLegacy,
            expected_revision: 7,
            renderer_generation: 4,
            verification_kind: None,
        };
        let result = super::super::dispatch::run_after_action_gate(request, || {
            prompt.set(prompt.get() + 1);
            spawn.set(spawn.get() + 1);
        });
        assert!(result.is_err());
        assert_eq!((prompt.get(), spawn.get()), (0, 0));

        let invalid = CredentialIntentIpc {
            action: CredentialIntentAction::Pair,
            renderer_generation: 0,
            ..request
        };
        let result = super::super::dispatch::run_after_action_gate(invalid, || {
            prompt.set(prompt.get() + 1);
            spawn.set(spawn.get() + 1);
        });
        assert!(result.is_err());
        assert_eq!((prompt.get(), spawn.get()), (0, 0));
    }
}
