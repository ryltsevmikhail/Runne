//! Structured-output request handling (REQ-PROV-123): the closed
//! `local-engine.structured-output.v1` namespace — `{ mode:
//! plain-json | schema-json, schema? }`. `plain-json` requires the
//! final output to parse as JSON; `schema-json` additionally requires
//! an in-subset schema whose canonical digest feeds the attempt
//! identity. There is NO unconstrained fallback: a rejected schema is
//! a rejected call.

use crate::structured_schema::{MAX_SCHEMA_BYTES, SchemaError, validate_schema_subset};
use serde_json::Value;
use sha2::Digest as _;

pub const STRUCTURED_NAMESPACE: &str = "local-engine.structured-output.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredMode {
    PlainJson,
    SchemaJson,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredRequest {
    pub mode: StructuredMode,
    /// Canonical schema bytes (schema-json only).
    pub canonical_schema: Option<String>,
    /// sha256 over the canonical schema (schema-json only).
    pub schema_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuredError {
    UnknownMode(String),
    SchemaRequired,
    /// Schema failed the v1 subset validation.
    Schema(SchemaError),
    Malformed,
}

impl std::fmt::Display for StructuredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownMode(m) => write!(f, "unknown structured mode: {m}"),
            Self::SchemaRequired => write!(f, "schema-json requires a schema"),
            Self::Schema(e) => write!(f, "schema subset: {e:?}"),
            Self::Malformed => write!(f, "malformed structured-output request"),
        }
    }
}

impl std::error::Error for StructuredError {}

impl StructuredRequest {
    /// Parses the namespace from a call extension; absent namespace →
    /// Ok(None) (unstructured generation is the default mode).
    pub fn from_extension(extension: &Value) -> Result<Option<Self>, StructuredError> {
        let Value::Object(ext) = extension else {
            return Ok(None);
        };
        let Some(inner) = ext.get(STRUCTURED_NAMESPACE) else {
            return Ok(None);
        };
        let Value::Object(m) = inner else {
            return Err(StructuredError::Malformed);
        };
        let mode = match m.get("mode") {
            Some(Value::String(s)) if s == "plain-json" => StructuredMode::PlainJson,
            Some(Value::String(s)) if s == "schema-json" => StructuredMode::SchemaJson,
            Some(Value::String(s)) => return Err(StructuredError::UnknownMode(s.clone())),
            _ => return Err(StructuredError::Malformed),
        };
        match mode {
            StructuredMode::PlainJson => {
                if m.contains_key("schema") {
                    // plain-json does not constrain by schema.
                    return Err(StructuredError::Malformed);
                }
                Ok(Some(Self {
                    mode,
                    canonical_schema: None,
                    schema_digest: String::new(),
                }))
            }
            StructuredMode::SchemaJson => {
                let schema = m.get("schema").ok_or(StructuredError::SchemaRequired)?;
                let canonical = serde_json_canonicalizer::to_string(schema)
                    .map_err(|_| StructuredError::Malformed)?;
                if canonical.len() > MAX_SCHEMA_BYTES {
                    return Err(StructuredError::Schema(SchemaError::TooLarge));
                }
                validate_schema_subset(&canonical).map_err(StructuredError::Schema)?;
                let digest = format!("sha256:{}", hex(&sha256(canonical.as_bytes())));
                Ok(Some(Self {
                    mode,
                    canonical_schema: Some(canonical),
                    schema_digest: digest,
                }))
            }
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, bytes);
    sha2::Digest::finalize(h).into()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
