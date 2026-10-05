use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError,
    ProviderToolDeclarationV1, ProviderToolNameV1, ProviderUsage, TextProviderProfile,
    ToolProviderProfile,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{OpenAiProfileError, OpenAiResponsesTextProfile};

/// Exact opt-in `OpenAI` Responses tool profile identity.
pub const OPENAI_RESPONSES_TOOL_PROFILE_ID: &str = "runne-linux-agent-tools-v1";
const TOOL_PROFILE_DOMAIN: &[u8] = b"GOCODE_OPENAI_RESPONSES_TOOL_PROFILE_V1\0";
const TOOL_SCHEMA_DOMAIN: &[u8] = b"GOCODE_OPENAI_RESPONSES_TOOL_SCHEMA_V1\0";

/// Explicitly enabled `OpenAI` profile that admits only the two fixed workspace tools.
#[derive(Debug, Clone)]
pub struct OpenAiResponsesToolProfile {
    text: OpenAiResponsesTextProfile,
    profile_digest: [u8; 32],
    schema_digest: [u8; 32],
    tools: [ProviderToolDeclarationV1; 2],
}

#[derive(Serialize)]
struct ProfileBinding<'a> {
    profile_id: &'a str,
    text_profile_digest: [u8; 32],
    tool_declarations: &'a [ProviderToolDeclarationV1; 2],
}

impl OpenAiResponsesToolProfile {
    /// Binds the fixed tool profile to one exact standard text profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the text profile is not an eligible foreground `OpenAI` profile
    /// or when its canonical schema binding cannot be encoded.
    pub fn new(text: OpenAiResponsesTextProfile) -> Result<Self, OpenAiProfileError> {
        if text.is_background() || text.provider_id() != "openai" {
            return Err(OpenAiProfileError::InvalidProfile);
        }
        let tools = [
            ProviderToolDeclarationV1::for_name(ProviderToolNameV1::WorkspaceFileRead),
            ProviderToolDeclarationV1::for_name(ProviderToolNameV1::WorkspaceFileCreateNew),
        ];
        let encoded = serde_json::to_vec(&ProfileBinding {
            profile_id: OPENAI_RESPONSES_TOOL_PROFILE_ID,
            text_profile_digest: text.profile_digest(),
            tool_declarations: &tools,
        })
        .map_err(|_| OpenAiProfileError::InvalidProfile)?;
        let schema_digest = domain_digest(
            TOOL_SCHEMA_DOMAIN,
            &serde_json::to_vec(&tools).map_err(|_| OpenAiProfileError::InvalidProfile)?,
        );
        let profile_digest = domain_digest(TOOL_PROFILE_DOMAIN, &encoded);
        Ok(Self {
            text,
            profile_digest,
            schema_digest,
            tools,
        })
    }

    /// Returns the tool profile digest, bound to the source text profile and exact schemas.
    #[must_use]
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    /// Returns the digest of the exact fixed tool schema list.
    #[must_use]
    pub const fn tool_schema_digest(&self) -> [u8; 32] {
        self.schema_digest
    }
    /// Returns the underlying exact text profile used for model and pricing identity.
    #[must_use]
    pub const fn text_profile(&self) -> &OpenAiResponsesTextProfile {
        &self.text
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

impl ProviderTerminalPricing for OpenAiResponsesToolProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        _effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        if pricing_revision_digest != &self.pricing_revision_digest()
            || profile_digest != &self.profile_digest
        {
            return Err(ProviderTerminalPricingError::Unavailable);
        }
        let amount = self
            .text
            .price_usage_micros(usage)
            .map_err(|error| match error {
                OpenAiProfileError::UnsupportedPricingTier | OpenAiProfileError::InvalidProfile => {
                    ProviderTerminalPricingError::Unavailable
                }
                OpenAiProfileError::PricingOverflow => ProviderTerminalPricingError::InvalidQuote,
            })?;
        ProviderPricedUsage::new(amount, self.currency().to_owned())
    }
}

impl TextProviderProfile for OpenAiResponsesToolProfile {
    fn profile_id(&self) -> &str {
        OPENAI_RESPONSES_TOOL_PROFILE_ID
    }
    fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    fn pricing_revision_digest(&self) -> [u8; 32] {
        self.text.pricing_revision_digest()
    }
    fn currency(&self) -> &str {
        self.text.currency()
    }
    fn max_input_bytes(&self) -> usize {
        self.text.max_input_bytes()
    }
    fn max_input_entries(&self) -> usize {
        self.text.max_input_entries()
    }
    fn max_input_entry_bytes(&self) -> usize {
        self.text.max_input_entry_bytes()
    }
    fn max_output_tokens(&self) -> u32 {
        self.text.max_output_tokens()
    }
    fn max_request_bytes(&self) -> usize {
        self.text.max_request_bytes()
    }
    fn price_usage_micros(
        &self,
        usage: ProviderUsage,
    ) -> Result<u64, ProviderTerminalPricingError> {
        self.text
            .price_usage_micros(usage)
            .map_err(|error| match error {
                OpenAiProfileError::UnsupportedPricingTier | OpenAiProfileError::InvalidProfile => {
                    ProviderTerminalPricingError::Unavailable
                }
                OpenAiProfileError::PricingOverflow => ProviderTerminalPricingError::InvalidQuote,
            })
    }
    fn call_binding_extension(&self) -> serde_json::Value {
        serde_json::json!({
            "profile_id": self.profile_id(),
            "profile_digest": hex::encode(self.profile_digest),
            "pricing_revision_digest": hex::encode(self.pricing_revision_digest()),
            "tool_schema_digest": hex::encode(self.schema_digest)
        })
    }
}

impl ToolProviderProfile for OpenAiResponsesToolProfile {
    fn tool_declarations(&self) -> &[ProviderToolDeclarationV1] {
        &self.tools
    }
}
