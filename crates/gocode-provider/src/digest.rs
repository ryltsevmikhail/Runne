use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ProviderCall;

const PROVIDER_CALL_DOMAIN: &[u8] = b"GOCODE_PROVIDER_CALL_V1\0";

/// Typed SHA-256 digest of a canonical provider call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderCallDigest([u8; 32]);

impl ProviderCallDigest {
    /// Returns the digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Failure to encode a provider call canonically.
#[derive(Debug, Error)]
pub enum CanonicalProviderError {
    /// Canonical JSON serialization rejected the call.
    #[error("provider call canonicalization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Calculates a domain-separated digest over RFC 8785 canonical JSON.
pub fn canonical_provider_call_digest(
    call: &ProviderCall,
) -> Result<ProviderCallDigest, CanonicalProviderError> {
    let bytes = serde_jcs::to_vec(call)?;
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_CALL_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(ProviderCallDigest(hasher.finalize().into()))
}
