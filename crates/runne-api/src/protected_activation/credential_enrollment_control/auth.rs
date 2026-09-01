/// Authenticates bounded native enrollment control frames with an independent key domain.
pub struct ProtectedCredentialEnrollmentAuthenticator {
    key: Zeroizing<[u8; 32]>,
}

impl ProtectedCredentialEnrollmentAuthenticator {
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            key: Zeroizing::new(derive_key(keys.readiness_key(), ENROLLMENT_CONTROL_DOMAIN)),
        }
    }

    pub fn issue_request(
        &self,
        binding: ProtectedCredentialEnrollmentRequestBinding,
        sequence: u64,
    ) -> Result<ProtectedCredentialEnrollmentRequest, LaunchAuthorityError> {
        if sequence == 0 {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        let unsigned = encode_request(&binding, sequence);
        Ok(ProtectedCredentialEnrollmentRequest {
            binding,
            sequence,
            proof: self.proof(REQUEST_PHASE, &unsigned),
        })
    }

    pub fn decode_request(
        &self,
        bytes: &[u8],
        expected: &ProtectedCredentialEnrollmentRequestBinding,
        previous_sequence: u64,
        now_unix_millis: u64,
    ) -> Result<VerifiedProtectedCredentialEnrollmentRequest, LaunchAuthorityError> {
        let request = self.decode_authenticated_request(
            bytes,
            previous_sequence,
            now_unix_millis,
        )?;
        if &request.binding != expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(request)
    }

    /// Authenticates a live request before daemon-owned policy validation.
    ///
    /// This value is not an authority; request/admission issuance remains the
    /// only path to a base authority and one-use intent proof.
    pub fn decode_authenticated_request(
        &self,
        bytes: &[u8],
        previous_sequence: u64,
        now_unix_millis: u64,
    ) -> Result<VerifiedProtectedCredentialEnrollmentRequest, LaunchAuthorityError> {
        let (unsigned, proof) = open(bytes, REQUEST_PHASE, REQUEST_BYTES)?;
        if now_unix_millis == 0 || !self.verifies(REQUEST_PHASE, unsigned, &proof) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        let (binding, sequence) = decode_request(unsigned)?;
        let expected_sequence = previous_sequence
            .checked_add(1)
            .ok_or(LaunchAuthorityError::RenewalReplay)?;
        if sequence != expected_sequence
            || now_unix_millis < binding.issued_at_unix_millis
            || now_unix_millis > binding.expires_at_unix_millis
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(VerifiedProtectedCredentialEnrollmentRequest {
            request_digest: request_digest(unsigned),
            binding,
            sequence,
            proof,
        })
    }

    pub fn issue_admission(
        &self,
        request: &VerifiedProtectedCredentialEnrollmentRequest,
        binding: ProtectedCredentialEnrollmentAdmissionBinding,
        sequence: u64,
    ) -> Result<ProtectedCredentialEnrollmentAdmission, LaunchAuthorityError> {
        if sequence == 0 {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        if !self.owns_request(request) || !admission_matches_request(request, &binding) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let unsigned = encode_admission(request.request_digest, &binding, sequence);
        Ok(ProtectedCredentialEnrollmentAdmission {
            request_digest: request.request_digest,
            binding,
            sequence,
            proof: self.proof(ADMISSION_PHASE, &unsigned),
        })
    }

    pub fn decode_admission(
        &self,
        bytes: &[u8],
        request: &VerifiedProtectedCredentialEnrollmentRequest,
        expected: &ProtectedCredentialEnrollmentAdmissionBinding,
        previous_sequence: u64,
        now_unix_millis: u64,
    ) -> Result<VerifiedProtectedCredentialEnrollmentAdmission, LaunchAuthorityError> {
        let admission = self.decode_authenticated_admission(
            bytes,
            request,
            previous_sequence,
            now_unix_millis,
        )?;
        if &admission.binding != expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(admission)
    }

    /// Authenticates the daemon's admission response without turning it into
    /// request authority. Callers must still compare every launch-known fact;
    /// only the daemon-side one-use registry may consume this candidate.
    pub fn decode_authenticated_admission(
        &self,
        bytes: &[u8],
        request: &VerifiedProtectedCredentialEnrollmentRequest,
        previous_sequence: u64,
        now_unix_millis: u64,
    ) -> Result<VerifiedProtectedCredentialEnrollmentAdmission, LaunchAuthorityError> {
        if !self.owns_request(request) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let (unsigned, proof) = open(bytes, ADMISSION_PHASE, ADMISSION_BYTES)?;
        if now_unix_millis == 0 || !self.verifies(ADMISSION_PHASE, unsigned, &proof) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        let (request_digest, binding, sequence) = decode_admission(unsigned)?;
        if request_digest != request.request_digest
            || sequence != next_sequence(previous_sequence)
            || !admission_matches_request(request, &binding)
            || !request_is_live_at(request, now_unix_millis)
            || now_unix_millis > binding.expires_at_unix_millis
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(VerifiedProtectedCredentialEnrollmentAdmission {
            request_digest,
            request_id: request.request_id(),
            binding,
            sequence,
            request_proof_binding: request.proof,
            admission_proof: proof,
        })
    }

    fn proof(&self, phase: u8, unsigned: &[u8]) -> [u8; 32] {
        authenticated_mac(
            &self.key,
            ENROLLMENT_CONTROL_DOMAIN,
            &[&[phase], unsigned].concat(),
        )
    }

    fn verifies(&self, phase: u8, unsigned: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.proof(phase, unsigned).ct_eq(proof))
    }

    fn owns_request(&self, request: &VerifiedProtectedCredentialEnrollmentRequest) -> bool {
        self.verifies(
            REQUEST_PHASE,
            &encode_request(&request.binding, request.sequence),
            &request.proof,
        )
    }

    fn owns_admission(&self, admission: &VerifiedProtectedCredentialEnrollmentAdmission) -> bool {
        self.verifies(
            ADMISSION_PHASE,
            &encode_admission(
                admission.request_digest,
                &admission.binding,
                admission.sequence,
            ),
            &admission.admission_proof,
        )
    }
}

impl std::fmt::Debug for ProtectedCredentialEnrollmentAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedCredentialEnrollmentAuthenticator(<redacted>)")
    }
}
