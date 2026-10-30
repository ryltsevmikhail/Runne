#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Exact-profile `DeepSeek` Responses text adapter contracts.

pub mod canary;
mod credential;
#[allow(missing_docs)]
mod decode_diagnostic;
mod profile;
mod render;
mod response_decode;
mod sse;
mod transport;

pub use credential::{DeepSeekCredentialError, DeepSeekCredentialMaterializer};
#[cfg(feature = "qualification-diagnostics")]
pub use decode_diagnostic::{
    DeepSeekDecodeDiagnostic, DeepSeekDecodeEventKind, DeepSeekDecodeField, DeepSeekDecodeIssue,
    DeepSeekDecodePhase, DeepSeekDecodeSchemaNode,
};
pub use profile::{
    DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DEEPSEEK_REQUEST_MODEL,
    DEEPSEEK_RESPONSES_PROFILE_ID, DeepSeekProfileError, DeepSeekResponsesTextProfile,
};
pub use render::{DeepSeekRenderError, DeepSeekResponsesTextRenderer};
#[cfg(feature = "qualification-diagnostics")]
pub use response_decode::decode_transport_response_with_diagnostic;
pub use response_decode::{decode_tool_transport_response, decode_transport_response};
pub use sse::{DeepSeekSseDecoder, DeepSeekStreamError};
pub use transport::{
    DEEPSEEK_MAX_DECODED_STREAM_BYTES, DEEPSEEK_MAX_NORMALIZED_TEXT_BYTES, DEEPSEEK_MAX_SSE_EVENTS,
    DEEPSEEK_MAX_SSE_FRAME_BYTES, DEEPSEEK_MAX_SSE_LINES, DEEPSEEK_MAX_TRANSPORT_CHUNKS,
    DeepSeekTransportError, DeepSeekTransportPolicy, DeepSeekTransportResponse,
};

impl runne_provider::TextProviderProfile for DeepSeekResponsesTextProfile {
    fn profile_id(&self) -> &str {
        self.profile_id()
    }
    fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest()
    }
    fn pricing_revision_digest(&self) -> [u8; 32] {
        self.pricing_revision_digest()
    }
    fn currency(&self) -> &str {
        self.currency()
    }
    fn max_input_bytes(&self) -> usize {
        self.max_input_bytes()
    }
    fn max_input_entries(&self) -> usize {
        self.max_input_entries()
    }
    fn max_input_entry_bytes(&self) -> usize {
        self.max_input_entry_bytes()
    }
    fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens()
    }
    fn max_request_bytes(&self) -> usize {
        self.max_request_bytes()
    }
    fn price_usage_micros(
        &self,
        usage: runne_provider::ProviderUsage,
    ) -> Result<u64, runne_provider::ProviderTerminalPricingError> {
        Self::price_usage_micros(self, usage).map_err(|error| match error {
            DeepSeekProfileError::PricingOverflow => {
                runne_provider::ProviderTerminalPricingError::InvalidQuote
            }
            DeepSeekProfileError::InvalidProfile
            | DeepSeekProfileError::UnsupportedPricingTier
            | DeepSeekProfileError::PricingUnavailable => {
                runne_provider::ProviderTerminalPricingError::Unavailable
            }
        })
    }
}

mod tool_inputs;
mod tool_profile;
mod tool_render;
pub use tool_profile::{DEEPSEEK_RESPONSES_TOOL_PROFILE_ID, DeepSeekResponsesToolProfile};
pub use tool_render::{DeepSeekResponsesToolRenderer, DeepSeekToolRenderError};
