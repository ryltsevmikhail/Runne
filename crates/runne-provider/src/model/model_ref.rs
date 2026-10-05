use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::id::{InvalidProviderId, ProviderCallId, ProviderId, bounded_identifier};

/// Exact provider/model/revision binding for historical execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelRef {
    provider_id: ProviderId,
    model_id: String,
    revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModelRef {
    provider_id: String,
    model_id: String,
    revision: String,
}

impl<'de> Deserialize<'de> for ModelRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawModelRef::deserialize(deserializer)?;
        let provider_id =
            ProviderId::new(raw.provider_id).map_err(<D::Error as serde::de::Error>::custom)?;

        ModelRef::new(provider_id, raw.model_id, raw.revision)
            .map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl ModelRef {
    /// Constructs an exact bounded model reference.
    pub fn new(
        provider_id: ProviderId,
        model_id: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, InvalidProviderId> {
        Ok(Self {
            provider_id,
            model_id: bounded_identifier(model_id.into())?,
            revision: bounded_identifier(revision.into())?,
        })
    }

    /// Returns the provider identity.
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the model identity.
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Returns the immutable model revision.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns a stable, domain-separated digest of the exact provider/model/revision tuple.
    ///
    /// Length prefixes prevent ambiguous concatenations and let durable recovery
    /// metadata bind a historical model without interpreting provider JSON.
    pub fn digest_v1(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hash = Sha256::new();
        hash.update(b"RUNNE_MODEL_REF_V1\0");
        for value in [self.provider_id.as_str(), self.model_id(), self.revision()] {
            hash.update((value.len() as u32).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.finalize().into()
    }
}

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
    /// A normalized text input must contain at least one byte.
    #[error("provider text input must not be empty")]
    EmptyTextInput,
    /// One normalized text input exceeded its byte bound.
    #[error("provider text input exceeds {max} bytes (actual {actual})")]
    TextInputTooLarge {
        /// Maximum accepted UTF-8 bytes for one input.
        max: usize,
        /// Actual UTF-8 byte length.
        actual: usize,
    },
    /// A call exceeded the bounded number of normalized text inputs.
    #[error("provider call exceeds {max} text inputs (actual {actual})")]
    TooManyTextInputs {
        /// Maximum accepted input entries.
        max: usize,
        /// Actual input entry count.
        actual: usize,
    },
    /// Aggregate normalized text input bytes exceeded the call bound.
    #[error("provider call text inputs exceed {max} bytes (actual {actual})")]
    TextInputsTooLarge {
        /// Maximum accepted aggregate UTF-8 bytes.
        max: usize,
        /// Actual aggregate UTF-8 byte length.
        actual: usize,
    },
    /// Tool declarations/results exceeded the bounded normalized context.
    #[error("provider tool context is malformed or exceeds its bound")]
    InvalidToolContext,
}

const MAX_EXTENSION_BYTES: usize = 16 * 1024;
const MAX_EXTENSION_DEPTH: usize = 16;
const MAX_REQUIRED_CAPABILITIES: usize = 32;
/// Maximum UTF-8 bytes accepted for one normalized provider input.
pub const MAX_PROVIDER_TEXT_INPUT_BYTES: usize = 64 * 1024;
/// Maximum normalized text input entries accepted for one provider call.
pub const MAX_PROVIDER_TEXT_INPUTS: usize = 64;
/// Maximum aggregate UTF-8 input bytes accepted for one provider call.
pub const MAX_PROVIDER_TEXT_INPUT_TOTAL_BYTES: usize = 256 * 1024;
/// Provider-neutral role of one canonical text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderInputRole {
    /// Runtime-owned instruction text.
    Developer,
    /// User-authored canonical input.
    User,
    /// Previously committed assistant text.
    Assistant,
}

/// One bounded provider-neutral text input with no credential material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderTextInput {
    role: ProviderInputRole,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderTextInput {
    role: ProviderInputRole,
    text: String,
}

impl<'de> Deserialize<'de> for ProviderTextInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderTextInput::deserialize(deserializer)?;
        Self::new(raw.role, raw.text).map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl ProviderTextInput {
    /// Constructs one bounded canonical text input.
    pub fn new(
        role: ProviderInputRole,
        text: impl Into<String>,
    ) -> Result<Self, ProviderCallError> {
        let text = text.into();
        if text.is_empty() {
            return Err(ProviderCallError::EmptyTextInput);
        }
        if text.len() > MAX_PROVIDER_TEXT_INPUT_BYTES {
            return Err(ProviderCallError::TextInputTooLarge {
                max: MAX_PROVIDER_TEXT_INPUT_BYTES,
                actual: text.len(),
            });
        }
        Ok(Self { role, text })
    }

    /// Returns the normalized input role.
    pub const fn role(&self) -> ProviderInputRole {
        self.role
    }

    /// Returns the exact input text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

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
    inputs: Vec<ProviderTextInput>,
    extension: Value,
    required_capabilities: Vec<ProviderCapability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tool_declarations: Vec<ProviderToolDeclarationV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tool_results: Vec<ProviderToolResultV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderCall {
    call_id: ProviderCallId,
    model_ref: ModelRef,
    manifest_digest: [u8; 32],
    max_output_tokens: u32,
    #[serde(default)]
    inputs: Vec<ProviderTextInput>,
    extension: Value,
    required_capabilities: Vec<ProviderCapability>,
    #[serde(default)]
    tool_declarations: Vec<ProviderToolDeclarationV1>,
    #[serde(default)]
    tool_results: Vec<ProviderToolResultV1>,
}
