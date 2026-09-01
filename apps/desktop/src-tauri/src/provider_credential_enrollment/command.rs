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
    pub(crate) const fn supported_d1_1a(self) -> bool {
        matches!(self.action, ProviderCredentialEnrollmentActionV2::Pair)
    }

    pub(crate) const fn writer_handoff_mode(
        self,
    ) -> runne_platform_desktop::CredentialWriterHandoffMode {
        match self.action {
            ProviderCredentialEnrollmentActionV2::Pair => {
                runne_platform_desktop::CredentialWriterHandoffMode::Pair
            }
            ProviderCredentialEnrollmentActionV2::Revoke
            | ProviderCredentialEnrollmentActionV2::MigrateLegacy => {
                runne_platform_desktop::CredentialWriterHandoffMode::ControlOnly
            }
        }
    }

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

    #[test]
    fn only_pair_selects_the_native_secret_relay_handoff() {
        use runne_platform_desktop::CredentialWriterHandoffMode;

        for (action, expected) in [
            (
                ProviderCredentialEnrollmentActionV2::Pair,
                CredentialWriterHandoffMode::Pair,
            ),
            (
                ProviderCredentialEnrollmentActionV2::Revoke,
                CredentialWriterHandoffMode::ControlOnly,
            ),
            (
                ProviderCredentialEnrollmentActionV2::MigrateLegacy,
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
    fn d1_1a_rejects_revoke_and_migration_before_native_work() {
        for action in [
            ProviderCredentialEnrollmentActionV2::Revoke,
            ProviderCredentialEnrollmentActionV2::MigrateLegacy,
        ] {
            assert!(
                !CredentialIntentIpc {
                    provider: ProviderCredentialProviderV2::OpenAi,
                    action,
                    expected_revision: 7,
                    renderer_generation: 4,
                    verification_kind: None,
                }
                .supported_d1_1a()
            );
        }
    }

    #[test]
    fn unsupported_action_gate_precedes_prompt_transition_and_writer() {
        let source = include_str!("dispatch.rs");
        let gate = source.find("run_after_pair_gate(request").unwrap();
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
    fn unsupported_action_dependency_gate_invokes_no_native_work() {
        let prompt = std::cell::Cell::new(0);
        let spawn = std::cell::Cell::new(0);
        let request = CredentialIntentIpc {
            provider: ProviderCredentialProviderV2::OpenAi,
            action: ProviderCredentialEnrollmentActionV2::Revoke,
            expected_revision: 7,
            renderer_generation: 4,
            verification_kind: None,
        };
        let result = super::super::dispatch::run_after_pair_gate(request, || {
            prompt.set(prompt.get() + 1);
            spawn.set(spawn.get() + 1);
        });
        assert!(result.is_err());
        assert_eq!((prompt.get(), spawn.get()), (0, 0));
    }
}
