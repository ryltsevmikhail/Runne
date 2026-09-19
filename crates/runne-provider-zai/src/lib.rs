#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Exact Z.ai Coding Plan profile over the shared Chat Completions adapter.

use runne_provider::{
    CredentialDispatchCapability, CredentialFence, CredentialLifecycleRevision, ProviderFuture,
};
use runne_provider_chat_completions::{
    ChatCompletionsProfile, ChatCompletionsRenderer, ChatCompletionsThinkingMode,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Stable provider identity.
pub const ZAI_PROVIDER_ID: &str = "zai";
/// Exact profile identity.
pub const ZAI_PROFILE_ID: &str = "gocode-zai-coding-chat-completions-text/1";
/// Official Coding Plan model ID.
pub const ZAI_MODEL_ID: &str = "glm-5.2";
/// Profile revision pinned to the official model/endpoint contract.
pub const ZAI_MODEL_REVISION: &str = "2026-09-13";
/// Exact Coding Plan origin.
pub const ZAI_ORIGIN: &str = "https://api.z.ai";
/// Exact OpenAI-compatible Coding Plan path.
pub const ZAI_PATH: &str = "/api/coding/paas/v4/chat/completions";
/// Validates provider-specific credential shape without exposing it.
///
/// # Errors
///
/// Returns [`ZaiCredentialError::AccessDenied`] when the material is empty,
/// oversized, or contains control bytes.
pub fn validate_credential(bytes: &[u8]) -> Result<(), ZaiCredentialError> {
    if bytes.is_empty()
        || bytes.len() > 4_096
        || bytes
            .iter()
            .any(|byte| *byte == b'\r' || *byte == b'\n' || *byte == 0)
    {
        return Err(ZaiCredentialError::AccessDenied);
    }
    Ok(())
}

const PROFILE_DIGEST: [u8; 32] = [
    0x81, 0xc9, 0xe5, 0x4d, 0x74, 0x86, 0xf2, 0x3e, 0x9a, 0x96, 0xa1, 0xfd, 0x9e, 0xb9, 0x62, 0x0e,
    0xe7, 0x77, 0xaf, 0xf8, 0xa1, 0xe3, 0xfc, 0x58, 0x15, 0x0c, 0x82, 0x45, 0x9b, 0xa8, 0x49, 0xde,
];
const ACCOUNTING_DIGEST: [u8; 32] = [
    0x04, 0x84, 0xbd, 0xa9, 0xc5, 0x4b, 0x06, 0xba, 0xf7, 0xe2, 0xfb, 0x04, 0xf8, 0x30, 0x64, 0x36,
    0x11, 0x12, 0xf6, 0x9c, 0xfa, 0xe3, 0xb8, 0x80, 0x07, 0x37, 0x00, 0x84, 0x9d, 0x82, 0x7a, 0x00,
];

/// Creates the fixed Z.ai profile.
#[must_use]
pub const fn profile() -> ChatCompletionsProfile {
    ChatCompletionsProfile::new_with_thinking(
        ZAI_PROVIDER_ID,
        ZAI_PROFILE_ID,
        ZAI_MODEL_ID,
        ZAI_MODEL_REVISION,
        ZAI_ORIGIN,
        ZAI_PATH,
        PROFILE_DIGEST,
        ACCOUNTING_DIGEST,
        64,
        65_536,
        262_144,
        16_384,
        524_288,
        65_536,
        ChatCompletionsThinkingMode::ThinkingObjectDisabled,
    )
}

/// Creates the shared renderer bound to Z.ai.
///
/// # Errors
///
/// Returns the profile validation error if the fixed profile contract is
/// inconsistent.
pub fn renderer()
-> Result<ChatCompletionsRenderer, runne_provider_chat_completions::ChatCompletionsProfileError> {
    ChatCompletionsRenderer::new(profile())
}

/// Closed Z.ai credential materialization error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ZaiCredentialError {
    /// Credential absent.
    #[error("Z.ai credential unavailable")]
    Missing,
    /// Secure-store access denied.
    #[error("Z.ai credential access denied")]
    AccessDenied,
}

/// Native credential boundary for the Z.ai profile.
pub trait ZaiCredentialMaterializer: Send + Sync {
    /// Materializes a short-lived credential after effect admission.
    fn materialize(
        &self,
        capability: &CredentialDispatchCapability,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        effect_receipt_digest: [u8; 32],
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, ZaiCredentialError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider_chat_completions::ChatCompletionsThinkingMode::ThinkingObjectDisabled;

    #[test]
    fn profile_is_the_global_coding_plan_contract() {
        let profile = profile();
        assert_eq!(profile.provider_id(), "zai");
        assert_eq!(profile.model_id(), "glm-5.2");
        assert_eq!(profile.origin(), ZAI_ORIGIN);
        assert_eq!(profile.path(), ZAI_PATH);
        assert_eq!(profile.thinking_mode(), ThinkingObjectDisabled);
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
    fn credential_validation_is_bounded_and_single_line() {
        assert!(validate_credential(b"zai-key").is_ok());
        assert!(validate_credential(b"").is_err());
        assert!(validate_credential(b"zai-key\n").is_err());
        assert!(validate_credential(&vec![b'x'; 4_097]).is_err());
    }
}
