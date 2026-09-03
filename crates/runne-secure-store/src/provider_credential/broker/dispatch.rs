use runne_provider::{CredentialDispatchCapability, CredentialFence, CredentialLifecycleRevision};

use super::errors::BrokerError;
use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, SecureStoreError,
};

pub trait ProviderCredentialDispatchMaterializer: Send + Sync {
    /// Materializes only the version named by a current dispatch capability.
    ///
    /// # Errors
    ///
    /// Returns a closed stale-capability, access, missing, or backend error.
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;
}

/// Exact non-secret authority accompanying one point-of-use material read.
pub struct ProviderCredentialDispatchRead<'a> {
    capability: &'a CredentialDispatchCapability,
    lifecycle: CredentialLifecycleRevision,
    fence: CredentialFence,
    effect_receipt_digest: [u8; 32],
}

impl<'a> ProviderCredentialDispatchRead<'a> {
    /// Captures an already-authorized credential capability and the durable
    /// effect-start binding that permits exactly one native material read.
    ///
    /// # Errors
    ///
    /// Rejects a zero receipt digest rather than creating an unbound read.
    pub fn new(
        capability: &'a CredentialDispatchCapability,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        effect_receipt_digest: [u8; 32],
    ) -> Result<Self, SecureStoreError> {
        if effect_receipt_digest == [0; 32] {
            return Err(BrokerError::AccessDenied.into());
        }
        Ok(Self {
            capability,
            lifecycle,
            fence,
            effect_receipt_digest,
        })
    }

    /// Returns the store-issued native load capability.
    #[must_use]
    pub const fn capability(&self) -> &CredentialDispatchCapability {
        self.capability
    }

    /// Returns the lifecycle revision captured by the online dispatch CAS.
    #[must_use]
    pub const fn lifecycle(&self) -> CredentialLifecycleRevision {
        self.lifecycle
    }

    /// Returns the credential fence captured by the online dispatch CAS.
    #[must_use]
    pub const fn fence(&self) -> CredentialFence {
        self.fence
    }

    /// Returns the measured durable effect-start receipt.
    #[must_use]
    pub const fn effect_receipt_digest(&self) -> [u8; 32] {
        self.effect_receipt_digest
    }
}

pub(super) struct VersionStoreDispatchMaterializer<N> {
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> VersionStoreDispatchMaterializer<N> {
    pub(super) const fn new(native: N, access: ProviderCredentialAccessPolicy) -> Self {
        Self { native, access }
    }
}

impl<N> ProviderCredentialDispatchMaterializer for VersionStoreDispatchMaterializer<N>
where
    N: NativeProviderCredentialVersionStore,
{
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.native.load_version(read.capability(), &self.access)
    }
}
