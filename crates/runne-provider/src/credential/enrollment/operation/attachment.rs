use super::super::{CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId};

/// Digest-only proof that the protected host attached one exact live writer.
///
/// The process handle and native channel remain non-serializable platform
/// capabilities. The store retains only this continuation binding before it
/// permits a broker ticket to be issued.
#[derive(Debug, PartialEq, Eq)]
pub struct AttachCredentialProcess {
    operation_id: CredentialOperationId,
    continuation_binding_digest: CredentialBindingDigest,
}

impl AttachCredentialProcess {
    /// Builds one metadata-only attachment request.
    pub fn new(
        operation_id: CredentialOperationId,
        continuation_binding_digest: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        if continuation_binding_digest.as_bytes() == [0; 32] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            continuation_binding_digest,
        })
    }

    /// Returns the durable operation receiving the protected writer attachment.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }

    /// Returns the exact digest required for subsequent ticket issuance and claim.
    pub const fn continuation_binding_digest(&self) -> CredentialBindingDigest {
        self.continuation_binding_digest
    }
}
