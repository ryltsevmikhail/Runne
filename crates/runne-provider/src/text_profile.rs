//! Provider-neutral read surface for exact Responses text profiles.

use crate::pricing::{ProviderTerminalPricing, ProviderTerminalPricingError};
use crate::stream::ProviderUsage;

/// Non-secret read surface shared by every exact Responses text profile.
///
/// Each adapter pins its concrete profile and immutable digest. The daemon
/// composition consumes only this neutral surface so OpenAI, DeepSeek and
/// future Responses-API providers share one execution path without sharing
/// any mutable provider behavior.
pub trait TextProviderProfile: ProviderTerminalPricing + Send + Sync {
    /// Exact versioned profile identity.
    fn profile_id(&self) -> &str;
    /// Exact immutable profile byte digest.
    fn profile_digest(&self) -> [u8; 32];
    /// Exact pricing revision digest.
    fn pricing_revision_digest(&self) -> [u8; 32];
    /// Pricing currency, e.g. `USD`.
    fn currency(&self) -> &str;
    /// Exact maximum aggregate input bytes.
    fn max_input_bytes(&self) -> usize;
    /// Exact maximum input entry count.
    fn max_input_entries(&self) -> usize;
    /// Exact maximum single input entry bytes.
    fn max_input_entry_bytes(&self) -> usize;
    /// Exact maximum output tokens.
    fn max_output_tokens(&self) -> u32;
    /// Exact maximum rendered request bytes.
    fn max_request_bytes(&self) -> usize;
    /// Prices short-context usage; `Err` for an unsupported pricing tier.
    fn price_usage_micros(&self, usage: ProviderUsage)
    -> Result<u64, ProviderTerminalPricingError>;

    /// Builds the exact provider-call extension used by canonical projection.
    ///
    /// The default is limited to the three fields shared by existing text
    /// adapters. Profiles with additional binding state may override this
    /// method. Digests are derived after the profile digest exists, so this
    /// extension is never included in that digest's input.
    fn call_binding_extension(&self) -> serde_json::Value {
        serde_json::json!({
            "profile_id": self.profile_id(),
            "profile_digest": encode_digest(self.profile_digest()),
            "pricing_revision_digest": encode_digest(self.pricing_revision_digest()),
        })
    }
}

fn encode_digest(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
