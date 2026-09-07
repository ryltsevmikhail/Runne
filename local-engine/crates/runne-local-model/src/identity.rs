//! Identity: canonical digest (top-level `manifestDigest` omission only),
//! constant-time comparison, `ManifestID` construction.

use crate::error::ManifestError;
use crate::manifest::ModelManifestV1;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Lowercase `sha256:<hex>` over the JCS preimage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDigest(String);

impl ManifestDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time comparison of declared vs computed.
    pub fn ct_eq(&self, other: &str) -> bool {
        let a = self.0.as_bytes();
        let b = other.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

/// `ManifestID = local:{modelID}:{modelRevision}:{manifestDigest}`.
pub fn manifest_id(model_id: &str, model_revision: &str, digest: &ManifestDigest) -> String {
    format!("local:{model_id}:{model_revision}:{}", digest.0)
}

/// Digest of the JCS serialization of `value` with the top-level
/// `manifestDigest` member omitted; no other member is special.
pub fn compute_digest(value: &Value) -> Result<ManifestDigest, ManifestError> {
    let mut preimage = match value {
        Value::Object(map) => Value::Object(map.clone()),
        other => other.clone(),
    };
    if let Value::Object(map) = &mut preimage {
        map.remove("manifestDigest");
    }
    let canonical = serde_json_canonicalizer::to_string(&preimage)?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(ManifestDigest(format!("sha256:{}", hex_lower(&hash))))
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0F) as usize] as char);
    }
    out
}

/// Verified manifest: parse → canonical check → schema → digest binding.
#[derive(Debug, Clone)]
pub struct VerifiedModelManifest {
    digest: ManifestDigest,
    id: String,
    inner: crate::manifest::ModelManifestV1,
    canonical: String,
}

impl VerifiedModelManifest {
    pub fn digest(&self) -> &ManifestDigest {
        &self.digest
    }

    pub fn manifest_id(&self) -> &str {
        &self.id
    }

    pub fn model_id(&self) -> &str {
        &self.inner.model_id
    }

    pub fn model_revision(&self) -> &str {
        &self.inner.model_revision
    }

    pub fn artifacts(&self) -> &[crate::manifest::ArtifactRef] {
        &self.inner.artifacts
    }

    pub fn capabilities(&self) -> &crate::specs::Capabilities {
        &self.inner.capabilities
    }

    pub fn license(&self) -> &str {
        &self.inner.license
    }

    pub fn compatibility(&self) -> &crate::specs::Compatibility {
        &self.inner.compatibility
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}

impl ModelManifestV1 {
    /// Full Task 2 entry point (name kept as the plan specifies; the
    /// struct also carries the parse-free `validate`).
    ///
    /// Order: canonical form → typed schema → digest. Schema before digest
    /// so structurally hostile inputs report the structural reason; the
    /// declared digest's format is a Digest-class check (below).
    pub fn parse_and_verify(bytes: &[u8]) -> Result<VerifiedModelManifest, ManifestError> {
        let canonicalized = crate::canonical::canonicalize_strict(bytes)?;
        // Shape errors (unknown/missing fields, types) are Schema-class,
        // distinct from Json (syntax) above.
        let manifest: ModelManifestV1 = serde_json::from_value(canonicalized.value.clone())
            .map_err(|err| ManifestError::Schema(err.to_string()))?;
        manifest.validate()?;
        let declared = &manifest.manifest_digest;
        if !(declared.starts_with("sha256:")
            && declared.len() == 7 + 64
            && declared[7..].bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(ManifestError::Digest(format!(
                "malformed declared digest: {declared}"
            )));
        }
        let digest = compute_digest(&canonicalized.value)?;
        if !digest.ct_eq(declared) {
            return Err(ManifestError::Digest(format!(
                "declared {declared} does not match computed {}",
                digest.as_str()
            )));
        }
        Ok(VerifiedModelManifest {
            id: manifest_id(&manifest.model_id, &manifest.model_revision, &digest),
            digest,
            inner: manifest,
            canonical: canonicalized.canonical,
        })
    }
}
