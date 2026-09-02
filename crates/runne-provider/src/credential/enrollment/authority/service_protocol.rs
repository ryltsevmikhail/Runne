use std::sync::Arc;

use super::{CredentialEnrollmentStoreAuthority, EnrollmentAuthoritySeal};
use crate::credential::enrollment::CredentialBindingDigest;

/// Process-local runtime capability required to issue a mutation arm.
pub struct CredentialRuntimeArmAuthority {
    _seal: Arc<EnrollmentAuthoritySeal>,
}

/// Process-local capability required to issue read bindings.
pub struct CredentialRuntimeReadAuthority {
    seal: Arc<EnrollmentAuthoritySeal>,
}

/// Process-local authority that bridges a trusted effect-start into a read request.
pub struct CredentialDispatchEffectReceiptAuthority {
    _seal: Arc<EnrollmentAuthoritySeal>,
}

impl CredentialEnrollmentStoreAuthority {
    /// Derives the process-local mutation-arm issuer from the durable store authority.
    pub fn runtime_arm_authority(&self) -> CredentialRuntimeArmAuthority {
        CredentialRuntimeArmAuthority {
            _seal: self.seal.clone(),
        }
    }

    /// Derives the process-local read-binding issuer.
    pub fn runtime_read_authority(&self) -> CredentialRuntimeReadAuthority {
        CredentialRuntimeReadAuthority {
            seal: self.seal.clone(),
        }
    }

    /// Derives the trusted point-of-use receipt issuer from durable runtime authority.
    pub fn dispatch_effect_receipt_authority(&self) -> CredentialDispatchEffectReceiptAuthority {
        CredentialDispatchEffectReceiptAuthority {
            _seal: self.seal.clone(),
        }
    }
}

impl CredentialDispatchEffectReceiptAuthority {
    /// Binds an independently measured effect-start receipt to one read request.
    pub fn issue_point_of_use_read(
        &self,
        binding: crate::credential::enrollment::CredentialRuntimeReadBinding,
        measured_receipt: CredentialBindingDigest,
    ) -> Result<
        crate::credential::enrollment::CredentialPointOfUseReadRequest,
        crate::credential::enrollment::CredentialEnrollmentError,
    > {
        if !binding.belongs_to(&self._seal) {
            return Err(crate::credential::enrollment::CredentialEnrollmentError::InvalidEvidence);
        }
        let receipt = crate::credential::enrollment::CredentialDispatchEffectReceipt::
            from_trusted_effect_start(measured_receipt);
        Ok(crate::credential::enrollment::CredentialPointOfUseReadRequest::from_trusted_effect_start(
            binding, receipt,
        ))
    }
}

impl CredentialRuntimeReadAuthority {
    /// Issues one independently bound read identity under runtime authority.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_binding(
        &self,
        epoch: crate::credential::enrollment::CredentialServiceEpoch,
        installation_owner: [u8; 32],
        session: [u8; 16],
        runtime_generation: u64,
        release_binding: CredentialBindingDigest,
        provider: crate::ProviderId,
        version: crate::CredentialVersionRef,
        lifecycle_revision: crate::credential::enrollment::CredentialLifecycleRevision,
        fence: crate::credential::enrollment::CredentialFence,
        sequence: crate::credential::enrollment::CredentialServiceRequestSequence,
        correlation: crate::credential::enrollment::CredentialServiceCorrelation,
        deadline: crate::credential::enrollment::CredentialServiceDeadline,
    ) -> Result<
        crate::credential::enrollment::CredentialRuntimeReadBinding,
        crate::credential::enrollment::CredentialEnrollmentError,
    > {
        crate::credential::enrollment::CredentialRuntimeReadBinding::issue(
            self.seal.clone(),
            epoch,
            installation_owner,
            session,
            runtime_generation,
            release_binding,
            provider,
            version,
            lifecycle_revision,
            fence,
            sequence,
            correlation,
            deadline,
        )
    }

    /// Converts only a binding issued by this authority into metadata readback.
    pub fn issue_metadata_readback(
        &self,
        binding: crate::credential::enrollment::CredentialRuntimeReadBinding,
    ) -> Result<
        crate::credential::enrollment::CredentialMetadataReadbackRequest,
        crate::credential::enrollment::CredentialEnrollmentError,
    > {
        if !binding.belongs_to(&self.seal) {
            return Err(crate::credential::enrollment::CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(crate::credential::enrollment::CredentialMetadataReadbackRequest::from_issued(binding))
    }
}
