/// Authority-issued immutable non-secret identity of credential source input.
pub struct CredentialProvisionSource {
    revision_id: [u8; 16],
    seal: Arc<AuthoritySeal>,
}

/// Non-cloneable native create work issued only for durable PREPARED state.
pub struct CredentialNativeCreateClaim {
    reference: CredentialVersionRef,
    source_revision_id: [u8; 16],
    generation: u64,
    seal: Arc<AuthoritySeal>,
}

impl CredentialNativeCreateClaim {
    /// Exact version whose native bytes may be created idempotently.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        &self.reference
    }
}

impl core::fmt::Debug for CredentialNativeCreateClaim {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialNativeCreateClaim")
            .field("reference", &self.reference)
            .field("source", &"<opaque>")
            .field("authority", &"<opaque>")
            .finish()
    }
}

impl core::fmt::Debug for CredentialProvisionSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CredentialProvisionSource(<opaque>)")
    }
}
