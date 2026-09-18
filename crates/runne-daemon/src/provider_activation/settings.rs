//! Non-secret settings shared by dynamically configured provider routes.

/// Owner-selected non-secret accounting mode for dynamic providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderAccountingMode {
    /// Charge the exact bound PAYG rates.
    Payg,
    /// Charge no incremental amount; provider quota owns settlement.
    Subscription,
    /// Explicit token-plan quota accounting.
    TokenPlan,
}

/// Non-secret settings needed by dynamic provider routes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderActivationSettings {
    /// Validated Vertex project segment.
    pub(crate) vertex_project: Option<String>,
    /// Validated Vertex location segment.
    pub(crate) vertex_location: Option<String>,
    /// Pinned Radius catalog snapshot bytes.
    pub(crate) radius_catalog: Option<Vec<u8>>,
    /// Exact model selected from the Radius snapshot.
    pub(crate) radius_model_id: Option<String>,
    /// Non-secret revision label for the Radius snapshot.
    pub(crate) radius_revision: Option<String>,
    /// Explicit accounting choice for a configured provider.
    pub(crate) accounting_mode: Option<ProviderAccountingMode>,
    /// Azure resource host component for the Responses profile.
    pub(crate) responses_resource: Option<String>,
    /// Azure deployment component for the Responses profile.
    pub(crate) responses_deployment: Option<String>,
    /// Explicit Responses pricing/accounting contract digest.
    pub(crate) responses_pricing_digest: Option<[u8; 32]>,
    /// Owner configured PAYG input rate in micro-USD per million tokens.
    pub(crate) responses_input_micros_per_million: Option<u64>,
    /// Owner configured PAYG output rate in micro-USD per million tokens.
    pub(crate) responses_output_micros_per_million: Option<u64>,
    /// Owner configured PAYG cached-input rate in micro-USD per million tokens.
    pub(crate) responses_cached_input_micros_per_million: Option<u64>,
    /// Local output reservation bound for the Responses model.
    pub(crate) responses_max_output_tokens: Option<u32>,
    /// Owner supplied context bound for an arbitrary Azure logical model.
    pub(crate) responses_context_tokens: Option<u32>,
    /// Bedrock region, or Cloudflare account, for the Cloud route.
    pub(crate) cloud_region_or_account: Option<String>,
    /// Cloudflare AI Gateway name for the Cloud route.
    pub(crate) cloud_gateway: Option<String>,
    /// Explicit Cloud PAYG input rate in micro-USD per million tokens.
    pub(crate) cloud_input_micros_per_million: Option<u64>,
    /// Explicit Cloud PAYG output rate in micro-USD per million tokens.
    pub(crate) cloud_output_micros_per_million: Option<u64>,
    /// Explicit Cloud PAYG cached-input rate in micro-USD per million tokens.
    pub(crate) cloud_cached_input_micros_per_million: Option<u64>,
    /// Model context bound supplied by the owner.
    pub(crate) cloud_context_tokens: Option<u32>,
    /// Model output bound supplied by the owner.
    pub(crate) cloud_max_output_tokens: Option<u32>,
    /// Attested maximum output supported by the selected model.
    pub(crate) cloud_max_model_output_tokens: Option<u32>,
    /// Input entry bound supplied by the owner.
    pub(crate) cloud_max_input_entries: Option<usize>,
    /// Input entry byte bound supplied by the owner.
    pub(crate) cloud_max_input_entry_bytes: Option<usize>,
    /// Aggregate input byte bound supplied by the owner.
    pub(crate) cloud_max_input_bytes: Option<usize>,
    /// Aggregate request byte bound supplied by the owner.
    pub(crate) cloud_max_request_bytes: Option<usize>,
    /// Response frame byte bound supplied by the owner.
    pub(crate) cloud_max_response_frame_bytes: Option<usize>,
    /// Explicit Cloudflare Gateway billing route.
    pub(crate) cloud_gateway_billing: Option<String>,
}
