use std::sync::Arc;

use crate::{CredentialVersionRef, ProviderId};

use super::super::{
    CredentialBindingDigest, CredentialFence, CredentialLifecycleRevision, CredentialOperationId,
    CredentialVerificationKind, CredentialVerifierRevision, authority::EnrollmentAuthoritySeal,
};
use super::BeginCredentialVerification;

/// Store-issued bounded verification lease.
///
/// ```compile_fail
/// use runne_provider::{BeginCredentialVerification, CredentialVerificationLease};
/// let _: fn(BeginCredentialVerification) -> CredentialVerificationLease =
///     CredentialVerificationLease::new;
/// ```
#[derive(Debug)]
pub struct CredentialVerificationLease {
    begin: BeginCredentialVerification,
    active_credential_version: CredentialVersionRef,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl PartialEq for CredentialVerificationLease {
    fn eq(&self, other: &Self) -> bool {
        self.begin == other.begin
            && self.active_credential_version == other.active_credential_version
            && Arc::ptr_eq(&self.seal, &other.seal)
    }
}

impl Eq for CredentialVerificationLease {}

impl CredentialVerificationLease {
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        begin: BeginCredentialVerification,
        active_credential_version: CredentialVersionRef,
    ) -> Self {
        Self {
            begin,
            active_credential_version,
            seal,
        }
    }

    /// Returns the durable observation identity.
    pub const fn observation_id(&self) -> CredentialOperationId {
        self.begin.observation_id()
    }
    /// Returns the associated operation identity when one exists.
    pub const fn operation_id(&self) -> Option<CredentialOperationId> {
        self.begin.operation_id()
    }
    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        self.begin.provider()
    }
    /// Returns the exact verification kind.
    pub const fn kind(&self) -> CredentialVerificationKind {
        self.begin.kind()
    }
    /// Returns the accepted intent-proof digest.
    pub const fn intent_proof_digest(&self) -> CredentialBindingDigest {
        self.begin.intent_proof_digest()
    }
    /// Returns the provider verifier revision.
    pub const fn verifier_revision(&self) -> CredentialVerifierRevision {
        self.begin.verifier_revision()
    }
    /// Returns the absolute high-water expiry.
    pub const fn expires_at_high_water(&self) -> i64 {
        self.begin.expires_at_high_water()
    }
    /// Returns the exact ACTIVE credential version committed by the lease CAS.
    pub const fn active_credential_version(&self) -> &CredentialVersionRef {
        &self.active_credential_version
    }
    /// Returns the lifecycle revision committed by the lease CAS.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.begin.expected_lifecycle_revision()
    }
    /// Returns the credential fence committed by the lease CAS.
    pub const fn fence(&self) -> CredentialFence {
        self.begin.expected_prior_fence()
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }
}

/// Process-local authority to materialize a credential for one verification.
///
/// ```compile_fail
/// use runne_provider::{CredentialBindingDigest, CredentialVerificationCapability, CredentialVerificationLease};
/// let _: fn(CredentialVerificationLease, CredentialBindingDigest) -> CredentialVerificationCapability =
///     CredentialVerificationCapability::new;
/// ```
#[derive(Debug)]
pub struct CredentialVerificationCapability {
    lease: CredentialVerificationLease,
    binding_digest: CredentialBindingDigest,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl PartialEq for CredentialVerificationCapability {
    fn eq(&self, other: &Self) -> bool {
        self.lease == other.lease
            && self.binding_digest == other.binding_digest
            && Arc::ptr_eq(&self.seal, &other.seal)
    }
}

impl Eq for CredentialVerificationCapability {}

impl CredentialVerificationCapability {
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        lease: CredentialVerificationLease,
        binding_digest: CredentialBindingDigest,
    ) -> Self {
        Self {
            lease,
            binding_digest,
            seal,
        }
    }

    /// Returns the durable observation identity.
    pub const fn observation_id(&self) -> CredentialOperationId {
        self.lease.observation_id()
    }
    /// Returns the associated operation identity when one exists.
    pub const fn operation_id(&self) -> Option<CredentialOperationId> {
        self.lease.operation_id()
    }
    /// Returns the exact capability binding digest.
    pub const fn binding_digest(&self) -> CredentialBindingDigest {
        self.binding_digest
    }
    /// Returns the bounded store lease.
    pub const fn lease(&self) -> &CredentialVerificationLease {
        &self.lease
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal) && self.lease.belongs_to(seal)
    }
}
