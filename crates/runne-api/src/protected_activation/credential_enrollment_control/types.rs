/// Exact desktop-to-daemon security bindings for one enrollment request.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedCredentialEnrollmentRequestBinding {
    protected_launch_authority_id: [u8; 16],
    protected_session_id: [u8; 16],
    daemon_instance_id: [u8; 16],
    daemon_launch_generation: u64,
    desktop_supervisor_generation: u64,
    request_id: [u8; 16],
    release_tuple_digest: [u8; 32],
    tauri_peer_process_evidence_digest: [u8; 32],
    native_confirmation_digest: [u8; 32],
    broker_process_evidence_digest: [u8; 32],
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
}

impl ProtectedCredentialEnrollmentRequestBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: [u8; 16],
        session: [u8; 16],
        daemon: [u8; 16],
        launch: u64,
        supervisor: u64,
        request: [u8; 16],
        release: [u8; 32],
        peer: [u8; 32],
        confirmation: [u8; 32],
        broker: [u8; 32],
        issued: u64,
        expires: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if !valid_ids(&[authority, session, daemon, request])
            || !valid_digests(&[release, peer, confirmation, broker])
            || launch == 0
            || supervisor == 0
            || issued == 0
            || expires <= issued
            || expires - issued > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            protected_launch_authority_id: authority,
            protected_session_id: session,
            daemon_instance_id: daemon,
            daemon_launch_generation: launch,
            desktop_supervisor_generation: supervisor,
            request_id: request,
            release_tuple_digest: release,
            tauri_peer_process_evidence_digest: peer,
            native_confirmation_digest: confirmation,
            broker_process_evidence_digest: broker,
            issued_at_unix_millis: issued,
            expires_at_unix_millis: expires,
        })
    }
}

/// Exact daemon-to-desktop base-authority and evidence bindings for one candidate.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedCredentialEnrollmentAdmissionBinding {
    installation_identity: [u8; 32],
    release_tuple_digest: [u8; 32],
    protected_session_binding: [u8; 32],
    desktop_supervisor_generation: u64,
    daemon_authority_binding: [u8; 32],
    database_generation: u64,
    authenticated_tauri_peer_binding: [u8; 32],
    native_confirmation_digest: [u8; 32],
    broker_process_evidence_digest: [u8; 32],
    admission_id: [u8; 16],
    expires_at_unix_millis: u64,
}

impl ProtectedCredentialEnrollmentAdmissionBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation: [u8; 32],
        release: [u8; 32],
        session: [u8; 32],
        supervisor: u64,
        daemon: [u8; 32],
        database: u64,
        peer: [u8; 32],
        confirmation: [u8; 32],
        broker: [u8; 32],
        admission: [u8; 16],
        expires: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if !valid_ids(&[admission])
            || !valid_digests(&[
                installation,
                release,
                session,
                daemon,
                peer,
                confirmation,
                broker,
            ])
            || supervisor == 0
            || database == 0
            || expires == 0
            || expires == u64::MAX
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            installation_identity: installation,
            release_tuple_digest: release,
            protected_session_binding: session,
            desktop_supervisor_generation: supervisor,
            daemon_authority_binding: daemon,
            database_generation: database,
            authenticated_tauri_peer_binding: peer,
            native_confirmation_digest: confirmation,
            broker_process_evidence_digest: broker,
            admission_id: admission,
            expires_at_unix_millis: expires,
        })
    }
}

/// A locally issued, HMAC-authenticated control record.
pub enum ProtectedCredentialEnrollmentControlFrame {
    Request(ProtectedCredentialEnrollmentRequest),
    Admission(ProtectedCredentialEnrollmentAdmission),
}
pub struct ProtectedCredentialEnrollmentRequest {
    binding: ProtectedCredentialEnrollmentRequestBinding,
    sequence: u64,
    proof: [u8; 32],
}
pub struct ProtectedCredentialEnrollmentAdmission {
    request_digest: [u8; 32],
    binding: ProtectedCredentialEnrollmentAdmissionBinding,
    sequence: u64,
    proof: [u8; 32],
}

impl ProtectedCredentialEnrollmentControlFrame {
    #[must_use]
    pub fn encode_frame(&self) -> Vec<u8> {
        let (unsigned, proof) = match self {
            Self::Request(value) => (
                encode_request(&value.binding, value.sequence).to_vec(),
                value.proof,
            ),
            Self::Admission(value) => (
                encode_admission(value.request_digest, &value.binding, value.sequence).to_vec(),
                value.proof,
            ),
        };
        let mut frame = Vec::with_capacity(4 + unsigned.len() + proof.len());
        frame.extend_from_slice(
            &u32::try_from(unsigned.len() + proof.len())
                .unwrap_or(0)
                .to_be_bytes(),
        );
        frame.extend(unsigned);
        frame.extend(proof);
        frame
    }
}

impl std::fmt::Debug for ProtectedCredentialEnrollmentControlFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedCredentialEnrollmentControlFrame(<redacted>)")
    }
}

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
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.binding.request_id
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Verified admission candidate, not an authority or bearer capability. A daemon owner must retain and atomically consume its admission ID and exact claims before Task 5 authority issuance.
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
}
impl std::fmt::Debug for VerifiedProtectedCredentialEnrollmentAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedProtectedCredentialEnrollmentAdmission(<candidate>)")
    }
}
