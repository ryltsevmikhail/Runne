use std::{fmt, sync::Arc};

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, authority::EnrollmentAuthoritySeal,
};

/// Authority-sealed, metadata-only qualified release tuple for one enrollment operation.
pub struct CredentialQualifiedReleaseTuple {
    digest: CredentialBindingDigest,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl CredentialQualifiedReleaseTuple {
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        digest: CredentialBindingDigest,
    ) -> Self {
        Self { digest, seal }
    }

    /// Returns the non-secret canonical qualified release tuple digest.
    pub const fn digest(&self) -> CredentialBindingDigest {
        self.digest
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self::issue(self.seal.clone(), self.digest)
    }

    pub(crate) fn from_persisted(
        seal: Arc<EnrollmentAuthoritySeal>,
        digest: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        Ok(Self::issue(seal, digest))
    }
}

impl fmt::Debug for CredentialQualifiedReleaseTuple {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CredentialQualifiedReleaseTuple")
            .field(&self.digest)
            .finish()
    }
}

impl PartialEq for CredentialQualifiedReleaseTuple {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest && Arc::ptr_eq(&self.seal, &other.seal)
    }
}

impl Eq for CredentialQualifiedReleaseTuple {}
