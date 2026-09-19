use crate::{ProfileError, ResponsesAccounting, ResponsesProfile, ResponsesProvider};
use sha2::{Digest, Sha256};

/// Pinned Pi source revision used for the built-in model identities.
pub const PI_REFERENCE_REVISION: &str = "pi/71dca871bc80b6bc97be37f0ca3189399d651fff";
/// Model selected by the pinned OpenAI Codex catalog fixture.
pub const CODEX_MODEL: &str = "gpt-5.5";
/// Model selected by the pinned GitHub Copilot Responses catalog fixture.
pub const COPILOT_MODEL: &str = "gpt-5.3-codex";
/// Model selected by the pinned xAI Responses catalog fixture.
pub const XAI_MODEL: &str = "grok-4.3";
/// Stable digest for the Codex externally metered subscription contract.
pub const CODEX_SUBSCRIPTION_PRICING_DIGEST: [u8; 32] =
    hex_digest("c47e930840a04ca03050f882568d51be92b233bc958b77add8c9b599a536054a");
/// Stable digest for the Copilot externally metered subscription contract.
pub const COPILOT_SUBSCRIPTION_PRICING_DIGEST: [u8; 32] =
    hex_digest("ba24e62502cbef5734ab3889f801933a1c24cde105b4450580b106aab5c9f2a8");
/// Attested local reservation maximum for the pinned Codex model.
pub const CODEX_MAX_OUTPUT_TOKENS: u32 = 128_000;
/// Attested local reservation maximum for the pinned Copilot model.
pub const COPILOT_MAX_OUTPUT_TOKENS: u32 = 128_000;
/// Attested local reservation maximum for the pinned xAI model.
pub const XAI_MAX_OUTPUT_TOKENS: u32 = 30_000;

/// Derives a stable local accounting-contract digest from owner-supplied PAYG
/// rates. This records configuration provenance; it is not a vendor price.
pub fn derive_payg_pricing_digest(
    provider: ResponsesProvider,
    model: &str,
    input_micros_per_million: u64,
    output_micros_per_million: u64,
    cached_input_micros_per_million: u64,
) -> [u8; 32] {
    let provider_id = match provider {
        ResponsesProvider::OpenAiCodex => "openai-codex",
        ResponsesProvider::GithubCopilot => "github-copilot",
        ResponsesProvider::AzureOpenAi => "azure-openai-responses",
        ResponsesProvider::Xai => "xai",
    };
    let mut digest = Sha256::new();
    digest.update(b"runne/responses-payg-accounting/v1\0");
    digest.update(provider_id.as_bytes());
    digest.update([0]);
    digest.update(model.as_bytes());
    digest.update([0]);
    digest.update(input_micros_per_million.to_be_bytes());
    digest.update(output_micros_per_million.to_be_bytes());
    digest.update(cached_input_micros_per_million.to_be_bytes());
    digest.finalize().into()
}

const SUBSCRIPTION_LIMITS: (usize, usize, usize, usize) = (64, 65_536, 262_144, 524_288);
const XAI_LIMITS: (usize, usize, usize, usize) = (64, 65_536, 524_288, 1_048_576);
const AZURE_LIMITS: (usize, usize, usize, usize) = (64, 32_768, 262_144, 524_288);

const fn hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

const fn hex_digest(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    let mut output = [0; 32];
    let mut index = 0;
    while index < 32 {
        output[index] = (hex_digit(bytes[index * 2]) << 4) | hex_digit(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

/// Builds the Codex subscription profile. The digest comes from the authority's
/// subscription quota contract; no per-call USD estimate is implied.
pub fn codex_subscription_profile(
    max_output_tokens: u32,
    pricing_digest: [u8; 32],
) -> ResponsesProfile {
    ResponsesProfile::new(ResponsesProvider::OpenAiCodex, CODEX_MODEL)
        .with_model_revision(PI_REFERENCE_REVISION)
        .with_pricing_revision_digest(pricing_digest)
        .with_accounting(ResponsesAccounting::SubscriptionQuotaExternallyMetered)
        .with_limits(
            SUBSCRIPTION_LIMITS.0,
            SUBSCRIPTION_LIMITS.1,
            SUBSCRIPTION_LIMITS.2,
            SUBSCRIPTION_LIMITS.3,
        )
        .with_max_output_tokens(max_output_tokens)
}

/// Builds the Copilot subscription profile with its separate session-token auth lane.
pub fn copilot_subscription_profile(
    max_output_tokens: u32,
    pricing_digest: [u8; 32],
) -> ResponsesProfile {
    ResponsesProfile::new(ResponsesProvider::GithubCopilot, COPILOT_MODEL)
        .with_model_revision(PI_REFERENCE_REVISION)
        .with_pricing_revision_digest(pricing_digest)
        .with_accounting(ResponsesAccounting::SubscriptionQuotaExternallyMetered)
        .with_limits(
            SUBSCRIPTION_LIMITS.0,
            SUBSCRIPTION_LIMITS.1,
            SUBSCRIPTION_LIMITS.2,
            SUBSCRIPTION_LIMITS.3,
        )
        .with_max_output_tokens(max_output_tokens)
}

/// Builds an xAI PAYG profile for the pinned Grok model and caller-supplied
/// authoritative rates. Rates are never guessed by this adapter.
pub fn xai_payg_profile(
    max_output_tokens: u32,
    pricing_digest: [u8; 32],
    input_micros_per_million: u64,
    output_micros_per_million: u64,
    cached_input_micros_per_million: u64,
) -> ResponsesProfile {
    ResponsesProfile::new(ResponsesProvider::Xai, XAI_MODEL)
        .with_model_revision(PI_REFERENCE_REVISION)
        .with_pricing_revision_digest(pricing_digest)
        .with_accounting(ResponsesAccounting::Payg {
            input_micros_per_million,
            output_micros_per_million,
            cached_input_micros_per_million,
        })
        .with_limits(XAI_LIMITS.0, XAI_LIMITS.1, XAI_LIMITS.2, XAI_LIMITS.3)
        .with_max_output_tokens(max_output_tokens)
}

/// Builds Azure's v1 Responses profile. Deployment is sent as `model`; the
/// logical model and owner-supplied accounting contract remain separately bound.
pub fn azure_profile(
    resource: &str,
    deployment: &str,
    model: &str,
    max_output_tokens: u32,
    pricing_digest: [u8; 32],
    accounting: ResponsesAccounting,
) -> Result<ResponsesProfile, ProfileError> {
    ResponsesProfile::azure(resource, deployment, model).map(|profile| {
        profile
            .with_model_revision(PI_REFERENCE_REVISION)
            .with_pricing_revision_digest(pricing_digest)
            .with_accounting(accounting)
            .with_limits(
                AZURE_LIMITS.0,
                AZURE_LIMITS.1,
                AZURE_LIMITS.2,
                AZURE_LIMITS.3,
            )
            .with_max_output_tokens(max_output_tokens)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_bind_models_revision_and_subscription_accounting() {
        let codex = codex_subscription_profile(32_768, [1; 32]);
        assert_eq!(codex.model(), CODEX_MODEL);
        assert_eq!(codex.model_revision(), PI_REFERENCE_REVISION);
        assert_eq!(codex.currency(), "XXX");
        assert_eq!(
            codex.profile_id(),
            "gocode-responses/openai-codex/gpt-5.5/1"
        );
        let copilot = copilot_subscription_profile(32_768, [2; 32]);
        assert_eq!(copilot.model(), COPILOT_MODEL);
        assert_eq!(copilot.currency(), "XXX");
        assert_ne!(codex.profile_digest(), copilot.profile_digest());
    }

    #[test]
    fn xai_and_azure_require_explicit_accounting_inputs() {
        let xai = xai_payg_profile(8_192, [3; 32], 2_000_000, 10_000_000, 200_000);
        assert!(matches!(xai.accounting(), ResponsesAccounting::Payg { .. }));
        let azure = azure_profile(
            "tenant",
            "prod-deployment",
            "gpt-5.5",
            8_192,
            [4; 32],
            ResponsesAccounting::ExternallyBilledUnpriced,
        )
        .unwrap();
        assert_eq!(azure.request_model(), "prod-deployment");
        assert_eq!(azure.currency(), "XXX");
        assert!(
            azure_profile(
                "tenant.example",
                "prod",
                "gpt-5.5",
                1,
                [4; 32],
                ResponsesAccounting::ExternallyBilledUnpriced,
            )
            .is_err()
        );
    }

    #[test]
    fn pinned_model_reservation_bounds_are_conservative() {
        let codex =
            codex_subscription_profile(CODEX_MAX_OUTPUT_TOKENS, CODEX_SUBSCRIPTION_PRICING_DIGEST);
        assert_eq!(codex.max_output_tokens(), 128_000);
        assert!(codex.max_output_tokens() < 272_000);
        let xai = xai_payg_profile(
            XAI_MAX_OUTPUT_TOKENS,
            [7; 32],
            2_000_000,
            10_000_000,
            200_000,
        );
        assert_eq!(xai.max_output_tokens(), 30_000);
    }

    #[test]
    fn payg_contract_digest_is_stable_and_provider_bound() {
        let xai = derive_payg_pricing_digest(ResponsesProvider::Xai, XAI_MODEL, 2, 10, 0);
        assert_eq!(
            xai,
            derive_payg_pricing_digest(ResponsesProvider::Xai, XAI_MODEL, 2, 10, 0)
        );
        assert_ne!(
            xai,
            derive_payg_pricing_digest(ResponsesProvider::AzureOpenAi, XAI_MODEL, 2, 10, 0)
        );
    }
}
