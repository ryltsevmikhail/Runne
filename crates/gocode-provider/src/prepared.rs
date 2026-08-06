use core::fmt;

use sha2::{Digest, Sha256};

use crate::{PrepareError, ProviderCall, ProviderCallDigestVersion};

/// Content-addressed reference to a prepared non-secret request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreparedRequestRef {
    digest_version: ProviderCallDigestVersion,
    bytes: [u8; 32],
}

impl PreparedRequestRef {
    /// Returns the canonical provider-call digest version.
    pub const fn digest_version(&self) -> ProviderCallDigestVersion {
        self.digest_version
    }

    /// Returns the reference digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Immutable prepared request metadata. Credential material is absent.
#[derive(Clone, PartialEq)]
pub struct PreparedRequest {
    request_ref: PreparedRequestRef,
    render_digest: [u8; 32],
    rendered_bytes: Vec<u8>,
    call: ProviderCall,
}

impl fmt::Debug for PreparedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRequest")
            .field("request_ref", &self.request_ref)
            .field("render_digest", &self.render_digest)
            .field("rendered_bytes_len", &self.rendered_bytes.len())
            .finish_non_exhaustive()
    }
}

impl PreparedRequest {
    /// Deterministically constructs a credential-free prepared request.
    pub fn from_call(call: &ProviderCall) -> Result<Self, PrepareError> {
        Self::from_call_for_digest_version(call, ProviderCallDigestVersion::V2)
    }

    /// Reconstructs a credential-free request under one explicit digest contract.
    pub fn from_call_for_digest_version(
        call: &ProviderCall,
        digest_version: ProviderCallDigestVersion,
    ) -> Result<Self, PrepareError> {
        let rendered_bytes = crate::provider_call_wire_bytes_for_version(call, digest_version)
            .map_err(|error| PrepareError::Render(error.to_string()))?;
        Self::from_rendered_call_for_digest_version(call, digest_version, rendered_bytes)
    }

    /// Constructs an exact prepared request from adapter-rendered, credential-free bytes.
    pub fn from_rendered_call_for_digest_version(
        call: &ProviderCall,
        digest_version: ProviderCallDigestVersion,
        rendered_bytes: Vec<u8>,
    ) -> Result<Self, PrepareError> {
        if rendered_bytes.is_empty() || rendered_bytes.len() > 524_288 {
            return Err(PrepareError::RenderedRequestBound);
        }
        let digest = crate::canonical_provider_call_digest_for_version(call, digest_version)
            .map_err(|error| PrepareError::Render(error.to_string()))?;
        let render_digest = Sha256::digest(&rendered_bytes).into();
        Ok(Self {
            request_ref: PreparedRequestRef {
                digest_version: digest.version(),
                bytes: *digest.as_bytes(),
            },
            render_digest,
            rendered_bytes,
            call: call.clone(),
        })
    }

    /// Returns the content-addressed request reference.
    pub const fn request_ref(&self) -> PreparedRequestRef {
        self.request_ref
    }
    /// Returns the normalized source call.
    pub const fn call(&self) -> &ProviderCall {
        &self.call
    }
    /// Returns the SHA-256 digest of the exact credential-free rendered bytes.
    pub const fn render_digest(&self) -> &[u8; 32] {
        &self.render_digest
    }
    /// Returns the exact immutable credential-free bytes admitted for dispatch.
    pub fn rendered_bytes(&self) -> &[u8] {
        &self.rendered_bytes
    }
}
