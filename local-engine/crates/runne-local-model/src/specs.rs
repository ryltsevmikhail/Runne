//! Manifest specification objects and validated value-object newtypes.
//! All fields are private; access is via immutable accessors only.

use crate::error::ManifestError;
use serde::Deserialize;

pub(crate) const MAX_STRING_BYTES: usize = 2048;
pub(crate) const MAX_PROFILES: usize = 64;
pub(crate) const MAX_MODALITIES: usize = 16;

pub(crate) fn check_str(field: &str, s: &str) -> Result<(), ManifestError> {
    if s.is_empty() || s.len() > MAX_STRING_BYTES {
        return Err(ManifestError::Schema(format!(
            "{field}: empty or exceeds {MAX_STRING_BYTES} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn check_digest(field: &str, s: &str) -> Result<(), ManifestError> {
    if !s.starts_with("sha256:")
        || s.len() != 7 + 64
        || !s[7..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ManifestError::Schema(format!(
            "{field}: malformed sha256 digest"
        )));
    }
    Ok(())
}

/// Validated value-object newtype; deserialization goes through the
/// constructor, so a typed field can never hold an unvalidated value.
macro_rules! value_object {
    ($name:ident, $doc:literal, $digest:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            /// Validated constructor.
            pub fn new(value: &str) -> Result<Self, ManifestError> {
                let field = concat!("value object ", stringify!($name));
                check_str(field, value)?;
                if $digest {
                    check_digest(field, value)?;
                }
                Ok(Self(value.to_string()))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::new(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

value_object!(
    ArtifactDigest,
    "Content digest of a manifest artifact.",
    true
);
value_object!(BackendProfileId, "Identifier of a backend profile.", false);
value_object!(TokenizerRevision, "Tokenizer revision.", false);
value_object!(ChatTemplateRevision, "Chat template revision.", false);
value_object!(ToolProtocolRevision, "Tool protocol revision.", false);

macro_rules! spec_accessors {
    ($($name:ident -> $ty:ty),* $(,)?) => {
        $(pub fn $name(&self) -> &$ty { &self.$name })*
    };
    ($($name:ident: $ty:ty),* $(,)?) => {
        $(pub fn $name(&self) -> $ty { self.$name })*
    };
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenizerSpec {
    pub(crate) family: String,
    pub(crate) revision: String,
    pub(crate) config_digest: String,
}

impl TokenizerSpec {
    spec_accessors!(family -> str, revision -> str, config_digest -> str);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChatTemplateSpec {
    pub(crate) id: String,
    pub(crate) revision: String,
    pub(crate) source_digest: String,
}

impl ChatTemplateSpec {
    spec_accessors!(id -> str, revision -> str, source_digest -> str);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ToolProtocolSpec {
    pub(crate) id: String,
    pub(crate) revision: String,
    pub(crate) schema_digest: String,
    pub(crate) semantics: String,
}

impl ToolProtocolSpec {
    spec_accessors!(id -> str, revision -> str, schema_digest -> str, semantics -> str);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProvenanceSpec {
    pub(crate) source_uri: String,
    pub(crate) publisher: String,
    pub(crate) acquired_at: String,
    pub(crate) source_digest: String,
    /// Builder contract revision that produced the candidate (Task 17);
    /// optional because hand-written manifests predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) builder_revision: Option<String>,
}

impl ProvenanceSpec {
    spec_accessors!(source_uri -> str, publisher -> str, acquired_at -> str, source_digest -> str);

    /// Builder contract revision that produced the candidate, when the
    /// manifest came from the Task 17 builder.
    pub fn builder_revision(&self) -> Option<&str> {
        self.builder_revision.as_deref()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Capabilities {
    pub(crate) modalities: Vec<String>,
    pub(crate) streaming: bool,
    pub(crate) tools: bool,
    pub(crate) structured_output: bool,
    pub(crate) reasoning: bool,
    pub(crate) context_max_tokens: u64,
    pub(crate) output_max_tokens: u64,
}

impl Capabilities {
    spec_accessors!(modalities -> [String]);
    spec_accessors!(streaming: bool, tools: bool, structured_output: bool, reasoning: bool);
    spec_accessors!(context_max_tokens: u64, output_max_tokens: u64);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HardwareRequirements {
    pub(crate) os: String,
    pub(crate) arch: String,
    pub(crate) min_ram_bytes: u64,
}

impl HardwareRequirements {
    spec_accessors!(os -> str, arch -> str);
    spec_accessors!(min_ram_bytes: u64);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BackendProfileRef {
    pub(crate) id: String,
    pub(crate) revision: String,
}

impl BackendProfileRef {
    spec_accessors!(id -> str, revision -> str);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Compatibility {
    pub(crate) backend_profiles: Vec<BackendProfileRef>,
}

impl Compatibility {
    pub fn backend_profiles(&self) -> &[BackendProfileRef] {
        &self.backend_profiles
    }
}
