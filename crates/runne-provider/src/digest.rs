use sha2::{Digest, Sha256};
use thiserror::Error;

use serde::Serialize;

use crate::{ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderTextInput};

const PROVIDER_CALL_V1_DOMAIN: &[u8] = b"RUNNE_PROVIDER_CALL_V1\0";
const PROVIDER_CALL_V2_DOMAIN: &[u8] = b"RUNNE_PROVIDER_CALL_V2\0";

/// Version of the canonical provider-call bytes and domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderCallDigestVersion {
    /// Released provider-call contract without canonical text inputs.
    V1,
    /// Provider-call contract committing canonical text role/order/bytes.
    V2,
}

/// Typed SHA-256 digest of a canonical provider call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderCallDigest {
    version: ProviderCallDigestVersion,
    bytes: [u8; 32],
}

impl ProviderCallDigest {
    /// Returns the canonical digest contract version.
    pub const fn version(&self) -> ProviderCallDigestVersion {
        self.version
    }

    /// Returns the digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Failure to encode a provider call canonically.
#[derive(Debug, Error)]
pub enum CanonicalProviderError {
    /// Canonical JSON serialization rejected the call.
    #[error("provider call canonicalization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// V1 cannot represent V2 canonical text input semantics.
    #[error("provider call V1 digest cannot represent text inputs")]
    V1TextInputs,
}

#[derive(Serialize)]
struct CanonicalProviderCallV1<'a> {
    call_id: ProviderCallId,
    model_ref: &'a ModelRef,
    manifest_digest: &'a [u8; 32],
    max_output_tokens: u32,
    extension: &'a serde_json::Value,
    required_capabilities: &'a [ProviderCapability],
}

#[derive(Serialize)]
struct CanonicalProviderCallV2<'a> {
    call_id: ProviderCallId,
    model_ref: &'a ModelRef,
    manifest_digest: &'a [u8; 32],
    max_output_tokens: u32,
    inputs: &'a [ProviderTextInput],
    extension: &'a serde_json::Value,
    required_capabilities: &'a [ProviderCapability],
}

/// Calculates the current V2 domain-separated provider-call digest.
pub fn canonical_provider_call_digest(
    call: &ProviderCall,
) -> Result<ProviderCallDigest, CanonicalProviderError> {
    canonical_provider_call_digest_for_version(call, ProviderCallDigestVersion::V2)
}

/// Calculates one explicit version of the provider-call digest.
pub fn canonical_provider_call_digest_for_version(
    call: &ProviderCall,
    version: ProviderCallDigestVersion,
) -> Result<ProviderCallDigest, CanonicalProviderError> {
    let (domain, bytes) = match version {
        ProviderCallDigestVersion::V1 => {
            if !call.text_inputs().is_empty() {
                return Err(CanonicalProviderError::V1TextInputs);
            }
            (
                PROVIDER_CALL_V1_DOMAIN,
                serde_jcs::to_vec(&CanonicalProviderCallV1 {
                    call_id: call.call_id(),
                    model_ref: call.model_ref(),
                    manifest_digest: call.manifest_digest(),
                    max_output_tokens: call.max_output_tokens(),
                    extension: call.extension(),
                    required_capabilities: call.required_capabilities(),
                })?,
            )
        }
        ProviderCallDigestVersion::V2 => (
            PROVIDER_CALL_V2_DOMAIN,
            serde_jcs::to_vec(&CanonicalProviderCallV2 {
                call_id: call.call_id(),
                model_ref: call.model_ref(),
                manifest_digest: call.manifest_digest(),
                max_output_tokens: call.max_output_tokens(),
                inputs: call.text_inputs(),
                extension: call.extension(),
                required_capabilities: call.required_capabilities(),
            })?,
        ),
    };
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(ProviderCallDigest {
        version,
        bytes: hasher.finalize().into(),
    })
}

/// Serializes the exact credential-free provider-neutral wire envelope for one
/// digest contract. V1 deliberately omits the V2 `inputs` field.
pub fn provider_call_wire_bytes_for_version(
    call: &ProviderCall,
    version: ProviderCallDigestVersion,
) -> Result<Vec<u8>, CanonicalProviderError> {
    match version {
        ProviderCallDigestVersion::V1 => {
            if !call.text_inputs().is_empty() {
                return Err(CanonicalProviderError::V1TextInputs);
            }
            Ok(serde_json::to_vec(&CanonicalProviderCallV1 {
                call_id: call.call_id(),
                model_ref: call.model_ref(),
                manifest_digest: call.manifest_digest(),
                max_output_tokens: call.max_output_tokens(),
                extension: call.extension(),
                required_capabilities: call.required_capabilities(),
            })?)
        }
        ProviderCallDigestVersion::V2 => Ok(serde_json::to_vec(&CanonicalProviderCallV2 {
            call_id: call.call_id(),
            model_ref: call.model_ref(),
            manifest_digest: call.manifest_digest(),
            max_output_tokens: call.max_output_tokens(),
            inputs: call.text_inputs(),
            extension: call.extension(),
            required_capabilities: call.required_capabilities(),
        })?),
    }
}
