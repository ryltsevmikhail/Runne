#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Exact `QwenCloud` Token Plan profile over the shared Chat Completions adapter.

use runne_provider::{
    CredentialDispatchCapability, CredentialFence, CredentialLifecycleRevision, ProviderFuture,
};
use runne_provider_chat_completions::{ChatCompletionsProfile, ChatCompletionsRenderer};
use thiserror::Error;
use zeroize::Zeroizing;

/// Stable provider identity.
pub const QWENCLOUD_PROVIDER_ID: &str = "qwen-token-plan-individual";
/// Exact profile identity.
pub const QWENCLOUD_PROFILE_ID: &str = "gocode-qwencloud-token-chat-completions-text/1";
/// Official Token Plan model ID.
pub const QWENCLOUD_MODEL_ID: &str = "qwen3.8-max";
/// Profile revision pinned to the official model/endpoint contract.
pub const QWENCLOUD_MODEL_REVISION: &str = "2026-09-13";
/// Exact Token Plan Singapore origin.
pub const QWENCLOUD_ORIGIN: &str = "https://token-plan.ap-southeast-1.maas.aliyuncs.com";
/// Exact OpenAI-compatible Token Plan path.
pub const QWENCLOUD_PATH: &str = "/compatible-mode/v1/chat/completions";
/// Validates Token Plan key prefix and bounded single-line material.
///
/// # Errors
///
/// Returns an access-denied error when the key is absent, malformed, or exceeds
/// the bounded credential size.
pub fn validate_credential(bytes: &[u8]) -> Result<(), QwenCloudCredentialError> {
    if !bytes.starts_with(b"sk-sp-")
        || bytes.len() > 4_096
        || bytes
            .iter()
            .any(|byte| *byte == b'\r' || *byte == b'\n' || *byte == 0)
    {
        return Err(QwenCloudCredentialError::AccessDenied);
    }
    Ok(())
}

const PROFILE_DIGEST: [u8; 32] = [
    0xc9, 0x4c, 0xe8, 0x40, 0xb7, 0xbb, 0xbc, 0xda, 0x25, 0x10, 0x58, 0x77, 0x8b, 0x61, 0xaa, 0xe5,
    0xb4, 0xbf, 0xc9, 0x46, 0xa1, 0x6d, 0x7c, 0x35, 0x23, 0x2c, 0x09, 0x9d, 0xa7, 0xe2, 0x65, 0x9f,
];
const ACCOUNTING_DIGEST: [u8; 32] = [
    0x1b, 0xc9, 0x58, 0x0a, 0x61, 0x44, 0x39, 0xdd, 0xcd, 0x92, 0xd6, 0x95, 0xf5, 0xb1, 0x97, 0xce,
    0x9e, 0xc1, 0x1f, 0x88, 0x15, 0x84, 0x3e, 0x89, 0x34, 0x6b, 0x5d, 0xc3, 0xb6, 0x8c, 0x64, 0xd2,
];

/// Creates the fixed `QwenCloud` profile.
#[must_use]
pub const fn profile() -> ChatCompletionsProfile {
    ChatCompletionsProfile::new(
        QWENCLOUD_PROVIDER_ID,
        QWENCLOUD_PROFILE_ID,
        QWENCLOUD_MODEL_ID,
        QWENCLOUD_MODEL_REVISION,
        QWENCLOUD_ORIGIN,
        QWENCLOUD_PATH,
        PROFILE_DIGEST,
        ACCOUNTING_DIGEST,
        64,
        65_536,
        262_144,
        16_384,
        524_288,
        65_536,
    )
}

/// Creates the shared renderer bound to `QwenCloud`.
///
/// # Errors
///
/// Returns the profile validation error if the fixed profile contract is invalid.
pub fn renderer()
-> Result<ChatCompletionsRenderer, runne_provider_chat_completions::ChatCompletionsProfileError> {
    ChatCompletionsRenderer::new(profile())
}

/// Closed `QwenCloud` credential materialization error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum QwenCloudCredentialError {
    /// Credential absent.
    #[error("QwenCloud credential unavailable")]
    Missing,
    /// Secure-store access denied.
    #[error("QwenCloud credential access denied")]
    AccessDenied,
}

/// Native credential boundary for the `QwenCloud` Token Plan profile.
pub trait QwenCloudCredentialMaterializer: Send + Sync {
    /// Materializes a short-lived `sk-sp-` credential after effect admission.
    fn materialize(
        &self,
        capability: &CredentialDispatchCapability,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        effect_receipt_digest: [u8; 32],
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, QwenCloudCredentialError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider_chat_completions::ChatCompletionsThinkingMode::EnableThinkingFalse;

    #[test]
    fn profile_is_the_individual_token_plan_contract() {
        let profile = profile();
        assert_eq!(profile.provider_id(), "qwen-token-plan-individual");
        assert_eq!(profile.model_id(), "qwen3.8-max");
        assert_eq!(profile.origin(), QWENCLOUD_ORIGIN);
        assert_eq!(profile.path(), QWENCLOUD_PATH);
        assert_eq!(profile.thinking_mode(), EnableThinkingFalse);
        assert_eq!(
            profile.profile_digest(),
            profile.recomputed_profile_digest()
        );
        assert_eq!(
            profile.pricing_revision_digest(),
            profile.recomputed_pricing_revision_digest()
        );
    }

    #[test]
    fn credential_validation_requires_the_token_plan_prefix() {
        assert!(validate_credential(b"sk-sp-example").is_ok());
        assert!(validate_credential(b"sk-example").is_err());
        assert!(validate_credential(b"sk-sp-example\r").is_err());
        assert!(validate_credential(&vec![b'x'; 4_097]).is_err());
    }
}
