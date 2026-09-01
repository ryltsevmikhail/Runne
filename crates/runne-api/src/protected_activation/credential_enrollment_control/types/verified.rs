/// Verified request claims obtained only after protected-frame verification.
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_api::VerifiedProtectedCredentialEnrollmentRequest>();
/// ```
pub struct VerifiedProtectedCredentialEnrollmentRequest {
    request_digest: [u8; 32],
    binding: ProtectedCredentialEnrollmentRequestBinding,
    sequence: u64,
    proof: [u8; 32],
}

impl std::fmt::Debug for VerifiedProtectedCredentialEnrollmentRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedProtectedCredentialEnrollmentRequest(<authenticated>)")
    }
}

impl VerifiedProtectedCredentialEnrollmentRequest {
    #[must_use]
    pub const fn protected_launch_authority_id(&self) -> [u8; 16] {
        self.binding.protected_launch_authority_id
    }
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.binding.request_id
    }
    #[must_use]
    pub const fn protected_session_id(&self) -> [u8; 16] {
        self.binding.protected_session_id
    }
    #[must_use]
    pub const fn daemon_instance_id(&self) -> [u8; 16] {
        self.binding.daemon_instance_id
    }
    #[must_use]
    pub const fn daemon_launch_generation(&self) -> u64 {
        self.binding.daemon_launch_generation
    }
    #[must_use]
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.binding.desktop_supervisor_generation
    }
    #[must_use]
    pub const fn release_tuple_digest(&self) -> [u8; 32] {
        self.binding.release_tuple_digest
    }
    #[must_use]
    pub const fn tauri_peer_process_evidence_digest(&self) -> [u8; 32] {
        self.binding.tauri_peer_process_evidence_digest
    }
    #[must_use]
    pub const fn native_confirmation_digest(&self) -> [u8; 32] {
        self.binding.native_confirmation_digest
    }
    #[must_use]
    pub const fn broker_process_evidence_digest(&self) -> [u8; 32] {
        self.binding.broker_process_evidence_digest
    }
    #[must_use]
    pub const fn action_provider_revision_binding(&self) -> [u8; 32] {
        self.binding.action_provider_revision_binding
    }
    #[must_use]
    pub const fn command_identity_binding(&self) -> [u8; 32] {
        self.binding.command_identity_binding
    }
    #[must_use]
    pub const fn native_intent_digest(&self) -> [u8; 32] {
        self.binding.native_intent_digest
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.binding.expires_at_unix_millis
    }
    #[must_use]
    pub(crate) const fn request_proof_binding(&self) -> [u8; 32] {
        self.proof
    }
}

/// Verified admission candidate, not an authority or bearer capability. The admission stays bound to the request proof of its authenticator domain. A daemon owner must retain and atomically consume its admission ID and exact claims before Task 5 authority issuance.
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_api::VerifiedProtectedCredentialEnrollmentAdmission>();
/// ```
pub struct VerifiedProtectedCredentialEnrollmentAdmission {
    request_digest: [u8; 32],
    request_id: [u8; 16],
    binding: ProtectedCredentialEnrollmentAdmissionBinding,
    sequence: u64,
    request_proof_binding: [u8; 32],
    admission_proof: [u8; 32],
}
impl VerifiedProtectedCredentialEnrollmentAdmission {
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    #[must_use]
    pub const fn admission_id(&self) -> [u8; 16] {
        self.binding.admission_id
    }
    #[must_use]
    pub const fn installation_identity(&self) -> [u8; 32] {
        self.binding.installation_identity
    }
    #[must_use]
    pub const fn release_tuple_digest(&self) -> [u8; 32] {
        self.binding.release_tuple_digest
    }
    #[must_use]
    pub const fn protected_session_binding(&self) -> [u8; 32] {
        self.binding.protected_session_binding
    }
    #[must_use]
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.binding.desktop_supervisor_generation
    }
    #[must_use]
    pub const fn daemon_authority_binding(&self) -> [u8; 32] {
        self.binding.daemon_authority_binding
    }
    #[must_use]
    pub const fn database_generation(&self) -> u64 {
        self.binding.database_generation
    }
    #[must_use]
    pub const fn authenticated_tauri_peer_binding(&self) -> [u8; 32] {
        self.binding.authenticated_tauri_peer_binding
    }
    #[must_use]
    pub const fn native_confirmation_digest(&self) -> [u8; 32] {
        self.binding.native_confirmation_digest
    }
    #[must_use]
    pub const fn broker_process_evidence_digest(&self) -> [u8; 32] {
        self.binding.broker_process_evidence_digest
    }
    #[must_use]
    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.binding.expires_at_unix_millis
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub(crate) const fn request_proof_binding(&self) -> [u8; 32] {
        self.request_proof_binding
    }
}
impl std::fmt::Debug for VerifiedProtectedCredentialEnrollmentAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedProtectedCredentialEnrollmentAdmission(<candidate>)")
    }
}
