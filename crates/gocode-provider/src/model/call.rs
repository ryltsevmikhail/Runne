/// Invalid normalized provider call input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderCallError {
    /// The output-token bound must be non-zero.
    #[error("max output tokens must be greater than zero")]
    ZeroMaxOutputTokens,
    /// Provider-specific data exceeded the canonical serialized byte bound.
    #[error("provider extension exceeds {max} bytes (actual {actual})")]
    ExtensionTooLarge {
        /// Maximum accepted canonical JSON bytes.
        max: usize,
        /// Actual serialized JSON bytes.
        actual: usize,
    },
    /// Provider-specific data exceeded the supported nesting depth.
    #[error("provider extension exceeds maximum nesting depth")]
    ExtensionTooDeep,
    /// Credential-like fields are forbidden in the normalized non-secret call.
    #[error("provider extension contains credential-like field: {0}")]
    CredentialField(String),
    /// Required capabilities exceeded the bounded call contract.
    #[error("required capabilities exceed {max} entries (actual {actual})")]
    TooManyRequiredCapabilities {
        /// Maximum accepted capability entries.
        max: usize,
        /// Actual capability entry count.
        actual: usize,
    },
}

const MAX_EXTENSION_BYTES: usize = 16 * 1024;
const MAX_EXTENSION_DEPTH: usize = 16;
const MAX_REQUIRED_CAPABILITIES: usize = 32;

/// Normalized capability required by a provider call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    /// Ordered text streaming.
    Streaming,
    /// Provider-native tool declarations and calls.
    Tools,
    /// Image inputs.
    Images,
    /// Structured output schemas.
    StructuredOutput,
    /// Provider-native reasoning controls.
    Reasoning,
}

/// Normalized provider call with no credential material.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProviderCall {
    call_id: ProviderCallId,
    model_ref: ModelRef,
    manifest_digest: [u8; 32],
    max_output_tokens: u32,
    extension: Value,
    required_capabilities: Vec<ProviderCapability>,
}

#[derive(Deserialize)]
struct RawProviderCall {
    call_id: ProviderCallId,
    model_ref: ModelRef,
    manifest_digest: [u8; 32],
    max_output_tokens: u32,
    extension: Value,
    required_capabilities: Vec<ProviderCapability>,
}

impl<'de> Deserialize<'de> for ProviderCall {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderCall::deserialize(deserializer)?;
        let required_capabilities = normalize_required_capabilities(raw.required_capabilities)
            .map_err(<D::Error as serde::de::Error>::custom)?;

        ProviderCall::new(
            raw.call_id,
            raw.model_ref,
            raw.manifest_digest,
            raw.max_output_tokens,
            raw.extension,
        )
        .map(|call| call.with_required_capabilities(required_capabilities))
        .map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl ProviderCall {
    /// Constructs a normalized call with an explicit output bound.
    pub fn new(
        call_id: ProviderCallId,
        model_ref: ModelRef,
        manifest_digest: [u8; 32],
        max_output_tokens: u32,
        extension: Value,
    ) -> Result<Self, ProviderCallError> {
        if max_output_tokens == 0 {
            return Err(ProviderCallError::ZeroMaxOutputTokens);
        }
        validate_extension(&extension, 0)?;
        Ok(Self {
            call_id,
            model_ref,
            manifest_digest,
            max_output_tokens,
            extension,
            required_capabilities: Vec::new(),
        })
    }

    /// Replaces the required capability set with a sorted, deduplicated set.
    pub fn with_required_capabilities(
        mut self,
        mut required_capabilities: Vec<ProviderCapability>,
    ) -> Self {
        required_capabilities.sort_unstable();
        required_capabilities.dedup();
        self.required_capabilities = required_capabilities;
        self
    }

    /// Returns the durable call identity.
    pub fn call_id(&self) -> ProviderCallId {
        self.call_id
    }

    /// Returns the exact provider/model revision.
    pub const fn model_ref(&self) -> &ModelRef {
        &self.model_ref
    }

    /// Returns the immutable input manifest digest.
    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    /// Returns the exact output-token bound.
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    /// Returns provider-specific normalized extension data.
    pub const fn extension(&self) -> &Value {
        &self.extension
    }

    /// Returns the exact required capability set.
    pub fn required_capabilities(&self) -> &[ProviderCapability] {
        &self.required_capabilities
    }
}
