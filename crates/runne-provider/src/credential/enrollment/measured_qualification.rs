use std::sync::Arc;

use super::{
    CredentialBindingDigest, ProviderQualificationAdmissionFence,
    authority::EnrollmentAuthoritySeal,
};

/// Daemon-observed session facts; provenance belongs to the paired measurement issuer.
pub struct QualificationSessionBinding {
    /// Exact protected session digest.
    pub protected_session: CredentialBindingDigest,
    /// Exact attachment continuation.
    pub continuation: CredentialBindingDigest,
    /// Live runtime authority identity.
    pub runtime_authority: [u8; 16],
    /// Retained and live database generation.
    pub database_generation: u64,
    /// Retained and live launch generation.
    pub launch_generation: u64,
    /// Retained and live supervisor generation.
    pub supervisor_generation: u64,
}

/// Move-only verified native admission measured by one enrollment authority pair.
pub struct MeasuredQualificationAdmission {
    pub(super) seal: Arc<EnrollmentAuthoritySeal>,
    pub(super) metadata: ProviderQualificationAdmissionFence,
    pub(super) continuation: CredentialBindingDigest,
    pub(super) fingerprint: [u8; 32],
}

impl MeasuredQualificationAdmission {
    /// Non-authorizing metadata for the transaction replay ledger.
    pub const fn metadata(&self) -> &ProviderQualificationAdmissionFence {
        &self.metadata
    }
    /// Exact attached continuation measured by the daemon.
    pub const fn continuation_binding_digest(&self) -> CredentialBindingDigest {
        self.continuation
    }
    /// Complete signed native fact fingerprint retained by the daemon.
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    pub(super) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }
}
