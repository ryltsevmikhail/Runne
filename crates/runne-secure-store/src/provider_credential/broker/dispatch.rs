use runne_provider::{
    CredentialDispatchCapability, CredentialFence, CredentialLifecycleRevision,
    ProviderRemoteOperationProof,
};

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

    /// Materializes the current credential for one already store-issued
    /// remote recovery operation. The daemon must validate the persisted proof
    /// and current lifecycle head immediately before constructing this read.
    ///
    /// # Errors
    ///
    /// Returns an access error unless an implementation can securely
    /// materialize recovery credentials.
    fn materialize_recovery(
        &self,
        read: ProviderCredentialRecoveryRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let _ = read;
        Err(SecureStoreError::CredentialAccessDenied)
    }
}

/// Native-load metadata for a fresh exact recovery operation.
pub struct ProviderCredentialRecoveryRead<'a> {
    capability: &'a CredentialDispatchCapability,
    lifecycle: CredentialLifecycleRevision,
    fence: CredentialFence,
    proof: &'a ProviderRemoteOperationProof,
    credential_realm: &'a runne_provider::ProviderId,
}

impl<'a> ProviderCredentialRecoveryRead<'a> {
    /// Binds a current native capability to the operation proof reserved by
    /// the runtime store. This metadata does not itself authorize transport.
    ///
    /// # Errors
    ///
    /// Returns an access error when the capability does not name this realm or
    /// the operation proof is invalid.
    pub fn new(
        capability: &'a CredentialDispatchCapability,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        proof: &'a ProviderRemoteOperationProof,
        credential_realm: &'a runne_provider::ProviderId,
    ) -> Result<Self, SecureStoreError> {
        if capability.version_ref().provider() != credential_realm
            || proof.nonce() == [0; 16]
            || proof.expires_at_unix_seconds() == 0
        {
            return Err(BrokerError::AccessDenied.into());
        }
        Ok(Self {
            capability,
            lifecycle,
            fence,
            proof,
            credential_realm,
        })
    }

    #[must_use]
    pub const fn capability(&self) -> &CredentialDispatchCapability {
        self.capability
    }
    #[must_use]
    pub const fn lifecycle(&self) -> CredentialLifecycleRevision {
        self.lifecycle
    }
    #[must_use]
    pub const fn fence(&self) -> CredentialFence {
        self.fence
    }
    #[must_use]
    pub const fn proof(&self) -> &ProviderRemoteOperationProof {
        self.proof
    }
    #[must_use]
    pub const fn credential_realm(&self) -> &runne_provider::ProviderId {
        self.credential_realm
    }
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

    fn materialize_recovery(
        &self,
        read: ProviderCredentialRecoveryRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.native.load_version(read.capability(), &self.access)
    }
}
