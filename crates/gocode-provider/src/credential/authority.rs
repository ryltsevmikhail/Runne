use std::sync::Arc;

use super::{CredentialLease, CredentialLifecycleError, CredentialVersionRef};

#[derive(Debug)]
struct AuthoritySeal;

/// Creates paired lifecycle/native authority handles for one runtime process.
///
/// Capabilities from another pair are rejected even when they name the same
/// credential version. Neither handle nor any issued capability is serializable.
pub struct CredentialAuthorityPair {
    lifecycle: CredentialLifecycleAuthority,
    native: NativeCredentialAuthority,
}

impl CredentialAuthorityPair {
    /// Creates one isolated credential authority domain.
    #[must_use]
    pub fn new() -> Self {
        let dispatch = Arc::new(AuthoritySeal);
        let gc = Arc::new(AuthoritySeal);
        let deletion = Arc::new(AuthoritySeal);
        Self {
            lifecycle: CredentialLifecycleAuthority {
                dispatch: Arc::clone(&dispatch),
                gc: Arc::clone(&gc),
                deletion: Arc::clone(&deletion),
            },
            native: NativeCredentialAuthority {
                dispatch,
                gc,
                deletion,
            },
        }
    }

    /// Separates the store-owned issuer from the native-store verifier.
    pub fn split(self) -> (CredentialLifecycleAuthority, NativeCredentialAuthority) {
        (self.lifecycle, self.native)
    }
}

impl Default for CredentialAuthorityPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Store-owned issuer for active dispatch and exclusive collection claims.
#[derive(Clone)]
pub struct CredentialLifecycleAuthority {
    dispatch: Arc<AuthoritySeal>,
    gc: Arc<AuthoritySeal>,
    deletion: Arc<AuthoritySeal>,
}

impl CredentialLifecycleAuthority {
    /// Issues native load authority after the caller validated the durable row.
    #[must_use]
    pub fn issue_dispatch(&self, lease: CredentialLease) -> CredentialDispatchCapability {
        CredentialDispatchCapability {
            lease,
            seal: Arc::clone(&self.dispatch),
        }
    }

    /// Issues exclusive native deletion work after durable `GC_CLAIMED` CAS.
    #[must_use]
    pub fn issue_gc(&self, reference: CredentialVersionRef) -> CredentialGcClaim {
        CredentialGcClaim {
            reference,
            seal: Arc::clone(&self.gc),
        }
    }

    /// Verifies that the paired native backend completed this exact deletion.
    pub fn verify_deletion<'a>(
        &self,
        proof: &'a NativeCredentialDeletionProof,
    ) -> Result<&'a CredentialVersionRef, CredentialLifecycleError> {
        if Arc::ptr_eq(&self.deletion, &proof.seal) {
            Ok(&proof.reference)
        } else {
            Err(CredentialLifecycleError::StaleLease)
        }
    }
}

impl core::fmt::Debug for CredentialLifecycleAuthority {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CredentialLifecycleAuthority(<opaque>)")
    }
}

/// Native-store verifier for capabilities issued by one lifecycle authority.
#[derive(Clone)]
pub struct NativeCredentialAuthority {
    dispatch: Arc<AuthoritySeal>,
    gc: Arc<AuthoritySeal>,
    deletion: Arc<AuthoritySeal>,
}

impl NativeCredentialAuthority {
    /// Validates an active dispatch capability for this native backend.
    pub fn authorize_load<'a>(
        &self,
        capability: &'a CredentialDispatchCapability,
    ) -> Result<&'a CredentialVersionRef, CredentialLifecycleError> {
        if Arc::ptr_eq(&self.dispatch, &capability.seal) {
            Ok(capability.version_ref())
        } else {
            Err(CredentialLifecycleError::StaleLease)
        }
    }

    /// Validates an exclusive GC claim for this native backend.
    pub fn authorize_delete<'a>(
        &self,
        claim: &'a CredentialGcClaim,
    ) -> Result<&'a CredentialVersionRef, CredentialLifecycleError> {
        if Arc::ptr_eq(&self.gc, &claim.seal) {
            Ok(&claim.reference)
        } else {
            Err(CredentialLifecycleError::StaleLease)
        }
    }

    /// Produces deletion evidence only after a successful native delete.
    pub fn prove_deletion(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, CredentialLifecycleError> {
        self.authorize_delete(&claim)?;
        Ok(NativeCredentialDeletionProof {
            reference: claim.reference,
            seal: Arc::clone(&self.deletion),
        })
    }
}

impl core::fmt::Debug for NativeCredentialAuthority {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeCredentialAuthority(<opaque>)")
    }
}

/// Non-forgeable active lease/fence capability required for native load.
#[derive(Clone)]
pub struct CredentialDispatchCapability {
    lease: CredentialLease,
    seal: Arc<AuthoritySeal>,
}

impl CredentialDispatchCapability {
    /// Exact active credential version.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        self.lease.version_ref()
    }

    /// Exact authoritative active lease.
    pub const fn lease(&self) -> &CredentialLease {
        &self.lease
    }
}

impl core::fmt::Debug for CredentialDispatchCapability {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialDispatchCapability")
            .field("version", self.version_ref())
            .field("authority", &"<opaque>")
            .finish()
    }
}

/// Non-forgeable exclusive work item required for native deletion.
pub struct CredentialGcClaim {
    reference: CredentialVersionRef,
    seal: Arc<AuthoritySeal>,
}

impl CredentialGcClaim {
    /// Exact version exclusively owned by reconciliation.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        &self.reference
    }
}

impl core::fmt::Debug for CredentialGcClaim {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("CredentialGcClaim")
            .field(&self.reference)
            .finish()
    }
}

/// Opaque native deletion evidence consumed by the lifecycle tombstone CAS.
pub struct NativeCredentialDeletionProof {
    reference: CredentialVersionRef,
    seal: Arc<AuthoritySeal>,
}

impl core::fmt::Debug for NativeCredentialDeletionProof {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("NativeCredentialDeletionProof")
            .field(&self.reference)
            .finish()
    }
}
