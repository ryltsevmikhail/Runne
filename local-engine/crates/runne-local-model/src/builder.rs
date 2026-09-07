//! Deterministic manifest builder (REQ-PROV-121): a pure function over
//! artifact bytes and explicit user-supplied fields. It has NO
//! admission authority; registry decides. License and provenance are
//! never synthesized; the runtime floor cannot be lowered below the
//! builder's contract revision; identical inputs yield byte-identical
//! canonical manifest bytes.

use crate::builder_error::BuilderError;
use crate::gguf::CapturedValue;
use crate::gguf::inspect;
use crate::gguf_limits::MAX_TEMPLATE_BYTES;
use serde_json::{Value, json};
use sha2::Digest as _;
use std::io::Read;

/// Contract version this builder validates manifests against; recorded
/// as `minCompatibleRuntime` unless the user raises it.
pub const BUILDER_CONTRACT_VERSION: &str = "0.1.0";

/// User-supplied fields that CANNOT be derived from GGUF bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserSupplied {
    pub model_id: String,
    pub model_revision: String,
    /// SPDX expression or immutable license reference.
    pub license: Option<String>,
    pub provenance_source_uri: Option<String>,
    pub provenance_publisher: Option<String>,
    /// RFC 3339 acquisition timestamp.
    pub provenance_acquired_at: Option<String>,
    /// Optional user chat-template file bytes.
    pub chat_template: Option<Vec<u8>>,
    /// Optional explicit raise of `minCompatibleRuntime`.
    pub min_compatible_runtime: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateManifest {
    pub canonical_bytes: Vec<u8>,
    /// `sha256:<hex>` over the canonical bytes.
    pub manifest_digest: String,
    pub warnings: Vec<String>,
}

/// Reads the artifact stream, derives the manifest and emits canonical
/// bytes. Deterministic: no clocks, no host state, sorted structures.
pub fn build_candidate_manifest<R: Read>(
    artifact: &mut R,
    user: &UserSupplied,
    builder_revision: &str,
) -> Result<CandidateManifest, BuilderError> {
    // Bounded intake: the admission parser caps what it reads anyway,
    // but the stream itself is capped here for builder symmetry.
    let mut bytes = Vec::new();
    artifact
        .take(1024 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|_| BuilderError::SourceUnreadable)?;

    // Authority fields are never synthesized.
    if user.license.as_deref().unwrap_or("").is_empty() {
        return Err(BuilderError::LicenseMissing);
    }
    let source_uri = user
        .provenance_source_uri
        .as_deref()
        .unwrap_or("")
        .to_string();
    let publisher = user
        .provenance_publisher
        .as_deref()
        .unwrap_or("")
        .to_string();
    let acquired_at = user
        .provenance_acquired_at
        .as_deref()
        .unwrap_or("")
        .to_string();
    if source_uri.is_empty() || publisher.is_empty() || acquired_at.is_empty() {
        return Err(BuilderError::LicenseMissing);
    }

    let insp = inspect(&bytes).map_err(map_parse)?;
    let arch = insp
        .architecture
        .clone()
        .ok_or(BuilderError::ArtifactUnparseable)?;
    if arch != "llama" {
        return Err(BuilderError::UnsupportedFormat);
    }

    let tokenizer_family = match insp.metadata.get("tokenizer.ggml.model") {
        Some(CapturedValue::Text(t)) if !t.is_empty() => t.clone(),
        _ => return Err(BuilderError::ArtifactUnparseable),
    };
    let context = insp
        .metadata
        .iter()
        .find(|(k, _)| k.ends_with(".context_length"))
        .and_then(|(_, v)| match v {
            CapturedValue::U64(u) => Some(*u),
            _ => None,
        })
        .ok_or(BuilderError::ArtifactUnparseable)?;
    if context == 0 || context > u32::MAX as u64 {
        return Err(BuilderError::ArtifactUnparseable);
    }

    // Template: embedded wins over the user file; exactly one is fine.
    let embedded = match insp.metadata.get("tokenizer.chat_template") {
        Some(CapturedValue::Text(t)) => Some(t.clone()),
        _ => None,
    };
    if embedded.is_some() && user.chat_template.is_some() {
        return Err(BuilderError::DeterminismViolation);
    }
    let (template_source_id, template_bytes) = if let Some(t) = embedded {
        ("gguf-embedded", t.into_bytes())
    } else if let Some(f) = &user.chat_template {
        if f.is_empty() || f.len() as u64 > MAX_TEMPLATE_BYTES {
            return Err(BuilderError::TemplateMissing);
        }
        ("user-file", f.clone())
    } else {
        return Err(BuilderError::TemplateMissing);
    };

    // Runtime floor: user may raise, never lower below the builder.
    let floor = parse_version(builder_revision)?;
    let effective_runtime = match &user.min_compatible_runtime {
        Some(v) => {
            let got = parse_version(v)?;
            if got < floor {
                return Err(BuilderError::DeterminismViolation);
            }
            v.clone()
        }
        None => builder_revision.to_string(),
    };

    let tokenizer_config_digest = format!("sha256:{}", hex(&sha256(tokenizer_family.as_bytes(),)));
    let template_digest = format!("sha256:{}", hex(&sha256(&template_bytes)));
    let source_digest = format!("sha256:{}", hex(&sha256(&bytes)));

    // Minimal RAM estimate from file size (OQ-LE-005 default model):
    // 4x artifact, floored at 256 MiB. Recorded as a warning.
    let min_ram = (bytes.len() as u64)
        .saturating_mul(4)
        .max(256 * 1024 * 1024);

    let preimage = json!({
        "artifacts": [{
            "byteLength": bytes.len() as u64,
            "contentType": "application/gguf",
            "digest": source_digest,
            "role": "model",
        }],
        "capabilities": {
            "contextMaxTokens": context,
            "modalities": ["text"],
            "outputMaxTokens": context.min(4096),
            "reasoning": false,
            "streaming": true,
            "structuredOutput": false,
            "tools": false,
        },
        "chatTemplate": {
            "id": template_source_id,
            "revision": "1",
            "sourceDigest": template_digest,
        },
        "compatibility": {
            "backendProfiles": [{
                "id": "llama-cpp-cpu-macos-arm64-v1",
                "revision": "v1",
            }],
        },
        "format": "GGUF",
        "hardwareRequirements": {
            "arch": "arm64",
            "minRamBytes": min_ram,
            "os": "macos",
        },
        "license": user.license.clone().expect("checked above"),
        "minCompatibleRuntime": effective_runtime,
        "modelID": user.model_id,
        "modelRevision": user.model_revision,
        "provenance": {
            "acquiredAt": acquired_at,
            "builderRevision": builder_revision,
            "publisher": publisher,
            "sourceDigest": source_digest,
            "sourceUri": source_uri,
        },
        "schemaVersion": "ModelManifestV1",
        "tokenizer": {
            "configDigest": tokenizer_config_digest,
            "family": tokenizer_family,
            "revision": "1",
        },
    });

    let canonical = serde_json_canonicalizer::to_string(&preimage)
        .map_err(|_| BuilderError::DeterminismViolation)?;
    let digest = sha256(canonical.as_bytes());
    let manifest_digest = format!("sha256:{}", hex(&digest));
    let mut full = preimage;
    full["manifestDigest"] = Value::String(manifest_digest.clone());
    let canonical = serde_json_canonicalizer::to_string(&full)
        .map_err(|_| BuilderError::DeterminismViolation)?;

    Ok(CandidateManifest {
        canonical_bytes: canonical.into_bytes(),
        manifest_digest,
        warnings: vec![
            "hardware minRamBytes uses the default OQ-LE-005 estimate (4x artifact)".into(),
        ],
    })
}

fn map_parse(e: crate::error::ManifestError) -> BuilderError {
    use crate::error::ManifestError as E;
    match e {
        E::Schema(s) if s.contains("bad magic") || s.contains("unsupported revision") => {
            BuilderError::UnsupportedFormat
        }
        _ => BuilderError::ArtifactUnparseable,
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

/// Strict numeric `major.minor.patch`; non-numeric parts refuse.
fn parse_version(v: &str) -> Result<(u64, u64, u64), BuilderError> {
    let mut parts = v.split('.');
    let mut next = || {
        parts
            .next()
            .and_then(|p| p.parse::<u64>().ok())
            .ok_or(BuilderError::DeterminismViolation)
    };
    let major = next()?;
    let minor = next()?;
    let patch = next()?;
    if parts.next().is_some() {
        return Err(BuilderError::DeterminismViolation);
    }
    Ok((major, minor, patch))
}
