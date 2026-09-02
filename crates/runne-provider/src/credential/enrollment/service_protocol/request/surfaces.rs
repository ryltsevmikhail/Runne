use std::sync::Arc;

use super::super::{
    CredentialDispatchEffectReceipt, CredentialServiceCorrelation, CredentialServiceDeadline,
    CredentialServiceEpoch, CredentialServiceRequestSequence,
};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, authority::EnrollmentAuthoritySeal,
};
use crate::{CredentialVersionRef, ProviderId};

/// Independent authority-issued read binding with no mutation capability.
///
/// ```compile_fail
/// let _ = runne_provider::CredentialRuntimeReadBinding::new();
/// ```
#[derive(Clone, Debug)]
pub struct CredentialRuntimeReadBinding {
    authority_seal: Option<Arc<EnrollmentAuthoritySeal>>,
    epoch: CredentialServiceEpoch,
    installation_owner: [u8; 32],
    session: [u8; 16],
    runtime_generation: u64,
    release_binding: CredentialBindingDigest,
    provider: ProviderId,
    version: CredentialVersionRef,
    lifecycle_revision: CredentialLifecycleRevision,
    fence: CredentialFence,
    sequence: CredentialServiceRequestSequence,
    correlation: CredentialServiceCorrelation,
    deadline: CredentialServiceDeadline,
}

impl CredentialRuntimeReadBinding {
    /// Constructs an exact current-version read binding.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        authority_seal: Arc<EnrollmentAuthoritySeal>,
        epoch: CredentialServiceEpoch,
        installation_owner: [u8; 32],
        session: [u8; 16],
        runtime_generation: u64,
        release_binding: CredentialBindingDigest,
        provider: ProviderId,
        version: CredentialVersionRef,
        lifecycle_revision: CredentialLifecycleRevision,
        fence: CredentialFence,
        sequence: CredentialServiceRequestSequence,
        correlation: CredentialServiceCorrelation,
        deadline: CredentialServiceDeadline,
    ) -> Result<Self, CredentialEnrollmentError> {
        Self::build(
            Some(authority_seal),
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_wire(
        epoch: CredentialServiceEpoch,
        installation_owner: [u8; 32],
        session: [u8; 16],
        runtime_generation: u64,
        release_binding: CredentialBindingDigest,
        provider: ProviderId,
        version: CredentialVersionRef,
        lifecycle_revision: CredentialLifecycleRevision,
        fence: CredentialFence,
        sequence: CredentialServiceRequestSequence,
        correlation: CredentialServiceCorrelation,
        deadline: CredentialServiceDeadline,
    ) -> Result<Self, CredentialEnrollmentError> {
        Self::build(
            None,
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

    #[allow(clippy::too_many_arguments)]
    fn build(
        authority_seal: Option<Arc<EnrollmentAuthoritySeal>>,
        epoch: CredentialServiceEpoch,
        installation_owner: [u8; 32],
        session: [u8; 16],
        runtime_generation: u64,
        release_binding: CredentialBindingDigest,
        provider: ProviderId,
        version: CredentialVersionRef,
        lifecycle_revision: CredentialLifecycleRevision,
        fence: CredentialFence,
        sequence: CredentialServiceRequestSequence,
        correlation: CredentialServiceCorrelation,
        deadline: CredentialServiceDeadline,
    ) -> Result<Self, CredentialEnrollmentError> {
        if installation_owner == [0; 32]
            || session == [0; 16]
            || runtime_generation == 0
            || version.provider() != &provider
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            authority_seal,
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
        })
    }
    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        self.authority_seal
            .as_ref()
            .is_some_and(|issued| Arc::ptr_eq(issued, seal))
    }
    /// Returns the epoch.
    pub const fn epoch(&self) -> CredentialServiceEpoch {
        self.epoch
    }
    /// Returns the installation owner routed by the authenticated envelope.
    pub const fn installation_owner(&self) -> [u8; 32] {
        self.installation_owner
    }
    /// Returns protected session identity.
    pub const fn session(&self) -> [u8; 16] {
        self.session
    }
    /// Returns runtime generation.
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }
    /// Returns release binding.
    pub const fn release_binding(&self) -> CredentialBindingDigest {
        self.release_binding
    }
    /// Returns provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }
    /// Returns exact credential version.
    pub const fn version(&self) -> &CredentialVersionRef {
        &self.version
    }
    /// Returns lifecycle revision.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.lifecycle_revision
    }
    /// Returns dispatch fence.
    pub const fn fence(&self) -> CredentialFence {
        self.fence
    }
    /// Returns request sequence.
    pub const fn sequence(&self) -> CredentialServiceRequestSequence {
        self.sequence
    }
    /// Returns exact request correlation.
    pub const fn correlation(&self) -> CredentialServiceCorrelation {
        self.correlation
    }
    /// Returns deadline.
    pub const fn deadline(&self) -> CredentialServiceDeadline {
        self.deadline
    }
}

/// Runtime metadata readback bound independently from mutation authority.
#[derive(Clone, Debug)]
pub struct CredentialMetadataReadbackRequest(CredentialRuntimeReadBinding);
impl CredentialMetadataReadbackRequest {
    pub(crate) fn from_issued(binding: CredentialRuntimeReadBinding) -> Self {
        Self(binding)
    }
    /// Returns its read-only binding.
    pub const fn binding(&self) -> &CredentialRuntimeReadBinding {
        &self.0
    }
}

/// Service-ingress metadata read decoded without runtime issue authority.
///
/// ```compile_fail
/// fn cannot_promote(value: runne_provider::CredentialMetadataReadbackAdmission) {
///     let _ = runne_provider::CredentialServiceRequest::MetadataReadback(value);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct CredentialMetadataReadbackAdmission(CredentialRuntimeReadBinding);
impl CredentialMetadataReadbackAdmission {
    pub(crate) fn from_wire(binding: CredentialRuntimeReadBinding) -> Self {
        Self(binding)
    }
    /// Returns its decoded read-only binding.
    pub const fn binding(&self) -> &CredentialRuntimeReadBinding {
        &self.0
    }
}

/// Point-of-use read additionally bound to a trusted effect-start receipt.
#[derive(Clone, Debug)]
pub struct CredentialPointOfUseReadRequest {
    binding: CredentialRuntimeReadBinding,
    receipt: CredentialDispatchEffectReceipt,
}
impl CredentialPointOfUseReadRequest {
    pub(crate) const fn from_trusted_effect_start(
        binding: CredentialRuntimeReadBinding,
        receipt: CredentialDispatchEffectReceipt,
    ) -> Self {
        Self { binding, receipt }
    }
    /// Returns independent read binding.
    pub const fn binding(&self) -> &CredentialRuntimeReadBinding {
        &self.binding
    }
    /// Returns active effect-start receipt.
    pub const fn receipt(&self) -> CredentialDispatchEffectReceipt {
        self.receipt
    }
}

/// Service-ingress point-of-use read decoded without receipt-issue authority.
///
/// ```compile_fail
/// fn cannot_promote(value: runne_provider::CredentialPointOfUseReadAdmission) {
///     let _ = runne_provider::CredentialServiceRequest::PointOfUseRead(value);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct CredentialPointOfUseReadAdmission {
    binding: CredentialRuntimeReadBinding,
    receipt: CredentialDispatchEffectReceipt,
}
impl CredentialPointOfUseReadAdmission {
    pub(crate) const fn from_wire(
        binding: CredentialRuntimeReadBinding,
        receipt: CredentialDispatchEffectReceipt,
    ) -> Self {
        Self { binding, receipt }
    }
    /// Returns its decoded read-only binding.
    pub const fn binding(&self) -> &CredentialRuntimeReadBinding {
        &self.binding
    }
    /// Returns its decoded point-of-use receipt.
    pub const fn receipt(&self) -> CredentialDispatchEffectReceipt {
        self.receipt
    }
}
