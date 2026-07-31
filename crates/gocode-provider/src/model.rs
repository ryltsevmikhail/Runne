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
        .and_then(|call| call.with_text_inputs(raw.inputs))
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
            inputs: Vec::new(),
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

    /// Replaces normalized text inputs after enforcing count and aggregate bounds.
    pub fn with_text_inputs(
        mut self,
        inputs: Vec<ProviderTextInput>,
    ) -> Result<Self, ProviderCallError> {
        if inputs.len() > MAX_PROVIDER_TEXT_INPUTS {
            return Err(ProviderCallError::TooManyTextInputs {
                max: MAX_PROVIDER_TEXT_INPUTS,
                actual: inputs.len(),
            });
        }
        let actual = inputs
            .iter()
            .try_fold(0usize, |total, input| total.checked_add(input.text.len()))
            .unwrap_or(usize::MAX);
        if actual > MAX_PROVIDER_TEXT_INPUT_TOTAL_BYTES {
            return Err(ProviderCallError::TextInputsTooLarge {
                max: MAX_PROVIDER_TEXT_INPUT_TOTAL_BYTES,
                actual,
            });
        }
        self.inputs = inputs;
        Ok(self)
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

    /// Returns normalized text inputs in canonical provider order.
    pub fn text_inputs(&self) -> &[ProviderTextInput] {
        &self.inputs
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

fn validate_extension(value: &Value, depth: usize) -> Result<(), ProviderCallError> {
    if depth > MAX_EXTENSION_DEPTH {
        return Err(ProviderCallError::ExtensionTooDeep);
    }
    if depth == 0 {
        let actual = serde_json::to_vec(value)
            .map_err(|_| ProviderCallError::ExtensionTooLarge {
                max: MAX_EXTENSION_BYTES,
                actual: usize::MAX,
            })?
            .len();
        if actual > MAX_EXTENSION_BYTES {
            return Err(ProviderCallError::ExtensionTooLarge {
                max: MAX_EXTENSION_BYTES,
                actual,
            });
        }
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized = normalize_extension_key(key);
                if normalized.contains("secret")
                    || normalized.contains("password")
                    || normalized.contains("authorization")
                    || normalized.contains("api_key")
                    || normalized == "token"
                    || normalized.ends_with("_token")
                {
                    return Err(ProviderCallError::CredentialField(key.clone()));
                }
                validate_extension(child, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_extension(child, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize_extension_key(key: &str) -> String {
    let characters = key.chars().collect::<Vec<_>>();
    let mut normalized = String::with_capacity(key.len());

    for (index, character) in characters.iter().copied().enumerate() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase() {
                let previous = index
                    .checked_sub(1)
                    .and_then(|previous| characters.get(previous));
                let next = characters.get(index + 1);
                let separates_word = previous.is_some_and(|previous| {
                    previous.is_ascii_lowercase()
                        || previous.is_ascii_digit()
                        || (previous.is_ascii_uppercase()
                            && next.is_some_and(|next| next.is_ascii_lowercase()))
                });
                if separates_word && !normalized.ends_with('_') {
                    normalized.push('_');
                }
            }
            normalized.push(character.to_ascii_lowercase());
        } else if !normalized.is_empty() && !normalized.ends_with('_') {
            normalized.push('_');
        }
    }

    normalized.trim_matches('_').to_owned()
}

fn normalize_required_capabilities(
    mut required_capabilities: Vec<ProviderCapability>,
) -> Result<Vec<ProviderCapability>, ProviderCallError> {
    if required_capabilities.len() > MAX_REQUIRED_CAPABILITIES {
        return Err(ProviderCallError::TooManyRequiredCapabilities {
            max: MAX_REQUIRED_CAPABILITIES,
            actual: required_capabilities.len(),
        });
    }
    required_capabilities.sort_unstable();
    required_capabilities.dedup();
    Ok(required_capabilities)
}

/// Normalized terminal reason for a provider stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFinishReason {
    /// Normal stop.
    Stop,
    /// Provider requested tool execution.
    ToolCalls,
    /// Output limit reached.
    Length,
    /// Provider content filter stopped output.
    ContentFilter,
    /// Provider reported an error.
    Error,
    /// Runtime cancellation reached the provider.
    Cancelled,
    /// Unrecognized reason retained for diagnostics and fail-closed handling.
    Unknown {
        /// Bounded raw provider value.
        raw: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawProviderFinishReason {
    Stop,
    ToolCalls,
    Length,
    ContentFilter,
    Error,
    Cancelled,
    Unknown { raw: String },
}

impl<'de> Deserialize<'de> for ProviderFinishReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderFinishReason::deserialize(deserializer)?;
        let reason = match raw {
            RawProviderFinishReason::Stop => Self::Stop,
            RawProviderFinishReason::ToolCalls => Self::ToolCalls,
            RawProviderFinishReason::Length => Self::Length,
            RawProviderFinishReason::ContentFilter => Self::ContentFilter,
            RawProviderFinishReason::Error => Self::Error,
            RawProviderFinishReason::Cancelled => Self::Cancelled,
            RawProviderFinishReason::Unknown { raw } => {
                Self::unknown(raw).map_err(<D::Error as serde::de::Error>::custom)?
            }
        };
        Ok(reason)
    }
}

impl ProviderFinishReason {
    /// Constructs a bounded unknown reason without treating it as success.
    pub fn unknown(raw: impl Into<String>) -> Result<Self, InvalidProviderId> {
        Ok(Self::Unknown {
            raw: bounded_identifier(raw.into())?,
        })
    }
}
